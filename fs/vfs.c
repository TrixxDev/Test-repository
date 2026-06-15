#include "vfs.h"
#include "string.h"

#define MAX_MOUNTS 8

typedef struct {
    char        path[64];
    vfs_node_t *root;
    int         used;
} mount_t;

static mount_t mounts[MAX_MOUNTS];

void vfs_init(void)
{
    for (int i = 0; i < MAX_MOUNTS; i++)
        mounts[i].used = 0;
}

int vfs_mount(const char *path, vfs_node_t *root)
{
    for (int i = 0; i < MAX_MOUNTS; i++) {
        if (!mounts[i].used) {
            mounts[i].used = 1;
            mounts[i].root = root;
            size_t n = 0;
            while (path[n] && n < sizeof(mounts[i].path) - 1) {
                mounts[i].path[n] = path[n];
                n++;
            }
            mounts[i].path[n] = '\0';
            return 0;
        }
    }
    return -1;
}

/* Does `path` begin with mount prefix `mp` at a component boundary? */
static int prefix_matches(const char *mp, const char *path)
{
    size_t i = 0;
    while (mp[i]) {
        if (mp[i] != path[i])
            return 0;
        i++;
    }
    /* "/" matches everything; otherwise the next char must end the component. */
    if (i == 1 && mp[0] == '/')
        return 1;
    return path[i] == '\0' || path[i] == '/';
}

vfs_node_t *vfs_resolve(const char *path)
{
    if (!path || path[0] != '/')
        return NULL;

    /* Find the mount with the longest matching prefix. */
    mount_t *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < MAX_MOUNTS; i++) {
        if (!mounts[i].used)
            continue;
        if (prefix_matches(mounts[i].path, path)) {
            size_t len = strlen(mounts[i].path);
            if (len >= best_len) {
                best = &mounts[i];
                best_len = len;
            }
        }
    }
    if (!best)
        return NULL;

    /* Skip the mount prefix, then walk the remaining components. */
    const char *p = path + best_len;
    vfs_node_t *node = best->root;

    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;

        char comp[64];
        size_t n = 0;
        while (*p && *p != '/' && n < sizeof(comp) - 1)
            comp[n++] = *p++;
        comp[n] = '\0';

        node = vfs_finddir(node, comp);
        if (!node)
            return NULL;
    }
    return node;
}

int vfs_permitted(vfs_node_t *node, int uid, int want)
{
    if (!node)
        return 0;
    if (uid == 0)
        return 1;                       /* root bypasses permission checks */
    int bits = (uid == node->owner_uid) ? (int)((node->mode >> 6) & 7)
                                        : (int)(node->mode & 7);
    return (bits & want) == want;
}

int vfs_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf)
{
    if (node && node->ops && node->ops->read)
        return node->ops->read(node, off, size, buf);
    return -1;
}

int vfs_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf)
{
    if (node && node->ops && node->ops->write)
        return node->ops->write(node, off, size, buf);
    return -1;
}

int vfs_readdir(vfs_node_t *node, uint32_t index, char *name_out, uint32_t cap)
{
    if (node && node->ops && node->ops->readdir)
        return node->ops->readdir(node, index, name_out, cap);
    return -1;
}

vfs_node_t *vfs_finddir(vfs_node_t *node, const char *name)
{
    if (node && node->ops && node->ops->finddir)
        return node->ops->finddir(node, name);
    return NULL;
}

vfs_node_t *vfs_create(vfs_node_t *dir, const char *name, uint32_t flags)
{
    if (dir && dir->ops && dir->ops->create)
        return dir->ops->create(dir, name, flags);
    return NULL;
}
