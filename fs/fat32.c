#include "fat32.h"
#include "ata.h"
#include "kheap.h"
#include "string.h"

#define SECTOR_SIZE 512
#define CLUSTER_MAX 4096        /* upper bound on bytes-per-cluster we handle */
#define FAT_EOC     0x0FFFFFF8

typedef struct {
    uint16_t bytes_per_sec;
    uint8_t  sec_per_clus;
    uint16_t rsvd;
    uint8_t  num_fats;
    uint32_t fatsz;
    uint32_t root_clus;
    uint32_t data_start;        /* LBA of cluster 2 */
} fat_fs_t;

static fat_fs_t fat;
static vfs_ops_t fat_ops;

static uint32_t cluster_lba(uint32_t cluster)
{
    return fat.data_start + (cluster - 2) * fat.sec_per_clus;
}

/* Follow the FAT to the next cluster in a chain. */
static uint32_t fat_next(uint32_t cluster)
{
    uint32_t fat_off    = cluster * 4;
    uint32_t fat_sector = fat.rsvd + (fat_off / SECTOR_SIZE);
    uint32_t ent_off    = fat_off % SECTOR_SIZE;

    uint8_t sec[SECTOR_SIZE];
    if (ata_read_sectors(fat_sector, 1, sec) != 0)
        return FAT_EOC;

    uint32_t val;
    memcpy(&val, sec + ent_off, 4);
    return val & 0x0FFFFFFF;
}

static int read_cluster(uint32_t cluster, uint8_t *buf)
{
    return ata_read_sectors(cluster_lba(cluster), fat.sec_per_clus, buf);
}

/* Convert "name.ext" into the 11-byte padded 8.3 form. */
static void to_83(const char *name, char out[11])
{
    for (int i = 0; i < 11; i++)
        out[i] = ' ';

    int i = 0;
    while (name[i] && name[i] != '.' && i < 8) {
        char c = name[i];
        if (c >= 'a' && c <= 'z')
            c -= 32;
        out[i] = c;
        i++;
    }
    const char *dot = name;
    while (*dot && *dot != '.')
        dot++;
    if (*dot == '.') {
        dot++;
        int j = 0;
        while (dot[j] && j < 3) {
            char c = dot[j];
            if (c >= 'a' && c <= 'z')
                c -= 32;
            out[8 + j] = c;
            j++;
        }
    }
}

static vfs_node_t *make_node(const char *name, uint32_t flags,
                             uint32_t cluster, uint32_t size)
{
    vfs_node_t *n = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!n)
        return NULL;
    memset(n, 0, sizeof(*n));
    uint32_t i = 0;
    while (name[i] && i < 63) {
        n->name[i] = name[i];
        i++;
    }
    n->name[i] = '\0';
    n->flags = flags;
    n->inode = cluster;
    n->size  = size;
    /* FAT32 is a read-only medium with no on-disk permissions: present every
     * node as root-owned and world readable+executable (rwxr-xr-x). */
    n->mode      = 0755;
    n->owner_uid = 0;
    n->ops   = &fat_ops;
    return n;
}

/* Parse a directory's entries, invoking found() per regular entry. */
static int fat_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf)
{
    if (off >= node->size)
        return 0;
    if (off + size > node->size)
        size = node->size - off;

    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    uint8_t cbuf[CLUSTER_MAX];
    uint32_t cluster = node->inode;

    for (uint32_t skip = off / clus_bytes; skip > 0; skip--)
        cluster = fat_next(cluster);

    uint32_t pos  = off % clus_bytes;
    uint32_t done = 0;
    while (done < size && cluster >= 2 && cluster < FAT_EOC) {
        if (read_cluster(cluster, cbuf) != 0)
            break;
        uint32_t avail = clus_bytes - pos;
        uint32_t take  = (size - done < avail) ? size - done : avail;
        memcpy(buf + done, cbuf + pos, take);
        done += take;
        pos = 0;
        cluster = fat_next(cluster);
    }
    return (int)done;
}

/* Walk a directory; for index `want` (or matching `match83`) return its entry. */
static vfs_node_t *dir_scan(vfs_node_t *dir, const char *match83,
                            int want, char *name_out, uint32_t cap)
{
    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    uint8_t cbuf[CLUSTER_MAX];
    uint32_t cluster = dir->inode;
    int index = 0;

    while (cluster >= 2 && cluster < FAT_EOC) {
        if (read_cluster(cluster, cbuf) != 0)
            break;
        for (uint32_t o = 0; o < clus_bytes; o += 32) {
            uint8_t *e = cbuf + o;
            if (e[0] == 0x00)
                return NULL;            /* no more entries */
            if (e[0] == 0xE5)
                continue;               /* deleted */
            if (e[11] & 0x0F)
                continue;               /* long-name / volume label */

            uint32_t first = ((uint32_t)(*(uint16_t *)(e + 20)) << 16) |
                             (uint32_t)(*(uint16_t *)(e + 26));
            uint32_t fsize = *(uint32_t *)(e + 28);
            uint32_t flags = (e[11] & 0x10) ? VFS_DIR : VFS_FILE;

            if (match83) {
                if (memcmp(e, match83, 11) == 0) {
                    /* Recover a printable name from the 8.3 field. */
                    char nm[13];
                    int p = 0;
                    for (int i = 0; i < 8 && e[i] != ' '; i++)
                        nm[p++] = e[i];
                    if (e[8] != ' ') {
                        nm[p++] = '.';
                        for (int i = 8; i < 11 && e[i] != ' '; i++)
                            nm[p++] = e[i];
                    }
                    nm[p] = '\0';
                    return make_node(nm, flags, first, fsize);
                }
            } else if (index == want) {
                int p = 0;
                for (int i = 0; i < 8 && e[i] != ' ' && (uint32_t)p < cap - 1; i++)
                    name_out[p++] = e[i];
                if (e[8] != ' ' && (uint32_t)p < cap - 1) {
                    name_out[p++] = '.';
                    for (int i = 8; i < 11 && e[i] != ' ' && (uint32_t)p < cap - 1; i++)
                        name_out[p++] = e[i];
                }
                name_out[p] = '\0';
                return dir;             /* non-NULL = found */
            }
            index++;
        }
        cluster = fat_next(cluster);
    }
    return NULL;
}

static vfs_node_t *fat_finddir(vfs_node_t *node, const char *name)
{
    char want[11];
    to_83(name, want);
    return dir_scan(node, want, -1, NULL, 0);
}

static int fat_readdir(vfs_node_t *node, uint32_t index, char *name_out, uint32_t cap)
{
    return dir_scan(node, NULL, (int)index, name_out, cap) ? 0 : -1;
}

static vfs_ops_t fat_ops = {
    .read    = fat_read,
    .write   = NULL,
    .finddir = fat_finddir,
    .readdir = fat_readdir,
    .create  = NULL,
};

vfs_node_t *fat32_mount(void)
{
    uint8_t bpb[SECTOR_SIZE];
    if (ata_read_sectors(0, 1, bpb) != 0)
        return NULL;

    if (bpb[510] != 0x55 || bpb[511] != 0xAA)
        return NULL;

    fat.bytes_per_sec = *(uint16_t *)(bpb + 11);
    fat.sec_per_clus  = bpb[13];
    fat.rsvd          = *(uint16_t *)(bpb + 14);
    fat.num_fats      = bpb[16];
    fat.fatsz         = *(uint32_t *)(bpb + 36);
    fat.root_clus     = *(uint32_t *)(bpb + 44);

    if (fat.bytes_per_sec != SECTOR_SIZE ||
        (uint32_t)fat.bytes_per_sec * fat.sec_per_clus > CLUSTER_MAX)
        return NULL;

    fat.data_start = fat.rsvd + (uint32_t)fat.num_fats * fat.fatsz;

    return make_node("/", VFS_DIR, fat.root_clus, 0);
}
