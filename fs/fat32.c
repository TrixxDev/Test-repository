#include "fat32.h"
#include "ata.h"
#include "kheap.h"
#include "string.h"
#include "perf.h"
#include "prof.h"

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
    uint32_t total_sec;
    uint32_t count_clusters;    /* number of data clusters (valid: 2 .. 1+count) */
} fat_fs_t;

static fat_fs_t fat;
static vfs_ops_t fat_ops;

/* Per-node bookkeeping so a file's directory entry can be updated on write. */
typedef struct {
    uint32_t dir_cluster;       /* cluster holding this file's 32-byte entry */
    uint32_t entry_off;         /* byte offset of the entry within that cluster */
} fat_meta_t;

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

/* A data cluster is valid iff it is in [2, 1 + count_clusters]; reject anything
 * else so cluster_lba() can never address outside the data region (a corrupt FAT
 * entry or stray first-cluster otherwise reads/writes off the disk). */
static int cluster_valid(uint32_t cluster)
{
    return cluster >= 2 && cluster < 2 + fat.count_clusters;
}

static int read_cluster(uint32_t cluster, uint8_t *buf)
{
    if (!cluster_valid(cluster))
        return -1;
    return ata_read_sectors(cluster_lba(cluster), fat.sec_per_clus, buf);
}

static int write_cluster(uint32_t cluster, const uint8_t *buf)
{
    if (!cluster_valid(cluster))
        return -1;
    return ata_write_sectors(cluster_lba(cluster), fat.sec_per_clus, buf);
}

/* Write a FAT entry in every FAT copy (keeps the FATs consistent). */
static void fat_set_next(uint32_t cluster, uint32_t value)
{
    uint32_t fat_off    = cluster * 4;
    uint32_t sec_index  = fat_off / SECTOR_SIZE;
    uint32_t ent_off    = fat_off % SECTOR_SIZE;
    uint8_t sec[SECTOR_SIZE];

    for (uint32_t n = 0; n < fat.num_fats; n++) {
        uint32_t lba = fat.rsvd + n * fat.fatsz + sec_index;
        if (ata_read_sectors(lba, 1, sec) != 0)
            return;
        uint32_t cur;
        memcpy(&cur, sec + ent_off, 4);
        cur = (cur & 0xF0000000u) | (value & 0x0FFFFFFFu);   /* preserve high bits */
        memcpy(sec + ent_off, &cur, 4);
        ata_write_sectors(lba, 1, sec);
    }
}

/* Find a free cluster, mark it end-of-chain, and return it (0 if the disk is
 * full). Scans FAT[0] for a zero entry within the data-cluster range. */
static uint32_t fat_alloc_cluster(void)
{
    uint8_t sec[SECTOR_SIZE];
    uint32_t per_sec = SECTOR_SIZE / 4;
    uint32_t limit = 2 + fat.count_clusters;

    for (uint32_t s = 0; s < fat.fatsz; s++) {
        if (ata_read_sectors(fat.rsvd + s, 1, sec) != 0)
            return 0;
        for (uint32_t i = 0; i < per_sec; i++) {
            uint32_t cluster = s * per_sec + i;
            if (cluster < 2)
                continue;
            if (cluster >= limit)
                return 0;
            uint32_t val;
            memcpy(&val, sec + i * 4, 4);
            if ((val & 0x0FFFFFFFu) == 0) {
                fat_set_next(cluster, FAT_EOC);
                return cluster;
            }
        }
    }
    return 0;
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

static vfs_node_t *make_node(const char *name, uint32_t flags, uint32_t cluster,
                             uint32_t size, uint32_t dir_cluster, uint32_t entry_off)
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
    /* FAT32 has no on-disk permissions, so they are synthesised: nodes are
     * root-owned; files are rwxr-xr-x (read+exec for all) and directories are
     * rwxrwxrwx so the unprivileged shell can create files on the scratch disk.
     * (These reset on remount — a writable FS with real metadata is future
     * work.) */
    n->mode      = (flags & VFS_DIR) ? 0777 : 0755;
    n->owner_uid = 0;
    n->ops   = &fat_ops;
    if (dir_cluster >= 2) {
        fat_meta_t *m = (fat_meta_t *)kmalloc(sizeof(fat_meta_t));
        if (m) {
            m->dir_cluster = dir_cluster;
            m->entry_off   = entry_off;
            n->priv = m;
        }
    }
    return n;
}

/* Parse a directory's entries, invoking found() per regular entry. */
/* Phase 18.5.2: the real logic, renamed so fat_read() itself can be a thin
 * timing wrapper -- this has an early return (past EOF), and threading a
 * stat update through it would be more invasive than timing from outside. */
static int fat_read_impl(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf, int flags)
{
    (void)flags;    /* regular files never block */
    if (off >= node->size)
        return 0;
    if (size > node->size - off)            /* clamp without off+size overflow */
        size = node->size - off;

    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    /* static, not stack-allocated: fat_write_impl() below calls
     * fat_update_dirent() before it returns, and each has its own 4096-byte
     * cluster buffer -- two of those alive at once already equals a whole
     * thread's 8192-byte kernel stack (STACK_SIZE in kernel/scheduler.c),
     * leaving zero room for the interrupt frame, sys_write(), vfs_write(),
     * or anything else in the call chain. There's no guard page below the
     * stack, so the overflow doesn't fault immediately -- it silently
     * corrupts whatever kmalloc'd memory happens to sit next to it, which is
     * exactly what caused a real crash here: EIP ending up pointing into the
     * bytes of the string a `save` command had just written, well after
     * that process had already exited. Safe as `static` (instead of
     * threading a caller-supplied scratch buffer through every call site)
     * because drivers/ata.c's cluster I/O is synchronous PIO that never
     * yields, and this kernel has no SMP -- only one caller is ever
     * mid-cluster-I/O at a time. */
    static uint8_t cbuf[CLUSTER_MAX];
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

static int fat_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf, int flags)
{
    uint64_t t0 = perf_now_us();   /* Phase 18.5.2 */
    int n = fat_read_impl(node, off, size, buf, flags);
    g_kprof.fat_read_us += (unsigned)(perf_now_us() - t0);
    g_kprof.fat_read_calls++;
    return n;
}

/* Walk a directory; for index `want` (or matching `match83`) return its entry. */
static vfs_node_t *dir_scan(vfs_node_t *dir, const char *match83,
                            int want, char *name_out, uint32_t cap)
{
    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    static uint8_t cbuf[CLUSTER_MAX];   /* static: see fat_read_impl()'s comment above */
    uint32_t cluster = dir->inode;
    int index = 0;
    uint32_t guard = fat.count_clusters + 1;    /* a chain can't exceed all clusters */

    while (cluster >= 2 && cluster < FAT_EOC && guard--) {
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
                    return make_node(nm, flags, first, fsize, cluster, o);
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

/* Persist a file's first cluster + size into its directory entry. */
static void fat_update_dirent(vfs_node_t *node)
{
    fat_meta_t *m = (fat_meta_t *)node->priv;
    if (!m || m->dir_cluster < 2)
        return;
    static uint8_t cbuf[CLUSTER_MAX];   /* static: see fat_read_impl()'s comment above */
    if (read_cluster(m->dir_cluster, cbuf) != 0)
        return;
    uint8_t *e = cbuf + m->entry_off;
    uint16_t hi = (uint16_t)((node->inode >> 16) & 0xFFFF);
    uint16_t lo = (uint16_t)(node->inode & 0xFFFF);
    memcpy(e + 20, &hi, 2);
    memcpy(e + 26, &lo, 2);
    memcpy(e + 28, &node->size, 4);
    write_cluster(m->dir_cluster, cbuf);
}

/* Write `size` bytes at `off`, extending the cluster chain (and the file's
 * recorded size) as needed. Partial clusters are read-modified-written. */
/* Phase 18.5.2: renamed for the same reason as fat_read_impl() above -- this
 * one has several early returns (not a regular file, zero length, overflow,
 * cluster allocation failure). */
static int fat_write_impl(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf, int flags)
{
    (void)flags;    /* regular files never block */
    if (node->flags & VFS_DIR)
        return -1;
    if (size == 0)
        return 0;
    if (size > 0xFFFFFFFFu - off)           /* off + size would overflow */
        return -1;

    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    uint32_t end = off + size;
    uint32_t need = (end + clus_bytes - 1) / clus_bytes;
    if (need == 0)
        need = 1;

    /* Ensure the file has a first cluster. */
    uint32_t first = node->inode;
    if (first < 2) {
        first = fat_alloc_cluster();
        if (first == 0)
            return -1;
        node->inode = first;
    }

    /* Walk the chain, allocating clusters until it is `need` long. */
    uint32_t c = first;
    for (uint32_t have = 1; have < need; have++) {
        uint32_t nx = fat_next(c);
        if (nx < 2 || nx >= FAT_EOC) {
            uint32_t nc = fat_alloc_cluster();
            if (nc == 0)
                return -1;
            fat_set_next(c, nc);
            nx = nc;
        }
        c = nx;
    }

    /* Seek to the cluster containing `off`. */
    c = first;
    for (uint32_t skip = off / clus_bytes; skip > 0; skip--)
        c = fat_next(c);

    static uint8_t cbuf[CLUSTER_MAX];   /* static: see fat_read_impl()'s comment above */
    uint32_t pos  = off % clus_bytes;
    uint32_t done = 0;
    while (done < size && c >= 2 && c < FAT_EOC) {
        if (pos != 0 || size - done < clus_bytes)
            read_cluster(c, cbuf);          /* read-modify-write a partial cluster */
        uint32_t avail = clus_bytes - pos;
        uint32_t take  = (size - done < avail) ? size - done : avail;
        memcpy(cbuf + pos, buf + done, take);
        if (write_cluster(c, cbuf) != 0)
            break;
        done += take;
        pos = 0;
        if (done < size)
            c = fat_next(c);
    }

    if (off + done > node->size)
        node->size = off + done;
    fat_update_dirent(node);
    return (int)done;
}

static int fat_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf, int flags)
{
    uint64_t t0 = perf_now_us();   /* Phase 18.5.2 */
    int n = fat_write_impl(node, off, size, buf, flags);
    g_kprof.fat_write_us += (unsigned)(perf_now_us() - t0);
    g_kprof.fat_write_calls++;
    return n;
}

/* Create an empty regular file `name` in directory `node` (root dir for now). */
static vfs_node_t *fat_create(vfs_node_t *node, const char *name, uint32_t flags)
{
    if (flags & VFS_DIR)
        return NULL;                        /* subdirectory creation not yet supported */

    char n83[11];
    to_83(name, n83);

    uint32_t clus_bytes = (uint32_t)fat.bytes_per_sec * fat.sec_per_clus;
    static uint8_t cbuf[CLUSTER_MAX];   /* static: see fat_read_impl()'s comment above */
    uint32_t cluster = node->inode;

    while (cluster >= 2 && cluster < FAT_EOC) {
        if (read_cluster(cluster, cbuf) != 0)
            return NULL;
        for (uint32_t o = 0; o < clus_bytes; o += 32) {
            uint8_t *e = cbuf + o;
            if (e[0] == 0x00 || e[0] == 0xE5) {   /* free / end slot */
                memset(e, 0, 32);
                memcpy(e, n83, 11);
                e[11] = 0x20;                /* archive (regular file) */
                /* first cluster 0, size 0 — allocated lazily on first write */
                write_cluster(cluster, cbuf);
                return make_node(name, VFS_FILE, 0, 0, cluster, o);
            }
        }
        uint32_t nx = fat_next(cluster);
        if (nx < 2 || nx >= FAT_EOC)
            break;                           /* directory full (no auto-extend yet) */
        cluster = nx;
    }
    return NULL;
}

static vfs_ops_t fat_ops = {
    .read    = fat_read,
    .write   = fat_write,
    .finddir = fat_finddir,
    .readdir = fat_readdir,
    .create  = fat_create,
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
    fat.total_sec     = *(uint32_t *)(bpb + 32);

    if (fat.bytes_per_sec != SECTOR_SIZE ||
        (uint32_t)fat.bytes_per_sec * fat.sec_per_clus > CLUSTER_MAX)
        return NULL;

    fat.data_start = fat.rsvd + (uint32_t)fat.num_fats * fat.fatsz;
    fat.count_clusters = (fat.total_sec - fat.data_start) / fat.sec_per_clus;

    return make_node("/", VFS_DIR, fat.root_clus, 0, 0, 0);
}
