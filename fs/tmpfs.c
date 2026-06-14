#include "tmpfs.h"
#include "kheap.h"
#include "string.h"

#define TMPFS_MAX_CHILDREN 64

/* A tmpfs node embeds its vfs_node_t as the first member so a vfs_node_t* can
 * be cast straight to a tnode_t*. */
typedef struct tnode {
    vfs_node_t v;
    uint8_t   *data;
    uint32_t   cap;
    struct tnode *children[TMPFS_MAX_CHILDREN];
    int        nchild;
} tnode_t;

static vfs_ops_t tmpfs_ops;

static void set_name(char *dst, const char *src)
{
    size_t i = 0;
    while (src[i] && i < 63) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static tnode_t *new_node(const char *name, uint32_t flags)
{
    tnode_t *t = (tnode_t *)kmalloc(sizeof(tnode_t));
    if (!t)
        return NULL;
    memset(t, 0, sizeof(*t));
    set_name(t->v.name, name);
    t->v.flags = flags;
    t->v.ops = &tmpfs_ops;
    t->v.priv = t;
    return t;
}

static int tmpfs_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf)
{
    tnode_t *t = (tnode_t *)node;
    if (off >= node->size)
        return 0;
    if (off + size > node->size)
        size = node->size - off;
    memcpy(buf, t->data + off, size);
    return (int)size;
}

static int tmpfs_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf)
{
    tnode_t *t = (tnode_t *)node;
    uint32_t need = off + size;

    if (need > t->cap) {
        uint32_t newcap = t->cap ? t->cap : 64;
        while (newcap < need)
            newcap *= 2;
        uint8_t *nd = (uint8_t *)kmalloc(newcap);
        if (!nd)
            return -1;
        memset(nd, 0, newcap);
        if (t->data) {
            memcpy(nd, t->data, t->v.size);
            kfree(t->data);
        }
        t->data = nd;
        t->cap = newcap;
    }

    memcpy(t->data + off, buf, size);
    if (need > node->size)
        node->size = need;
    return (int)size;
}

static vfs_node_t *tmpfs_finddir(vfs_node_t *node, const char *name)
{
    tnode_t *t = (tnode_t *)node;
    for (int i = 0; i < t->nchild; i++)
        if (strcmp(t->children[i]->v.name, name) == 0)
            return &t->children[i]->v;
    return NULL;
}

static int tmpfs_readdir(vfs_node_t *node, uint32_t index, char *name_out, uint32_t cap)
{
    tnode_t *t = (tnode_t *)node;
    if ((int)index >= t->nchild)
        return -1;
    const char *n = t->children[index]->v.name;
    uint32_t i = 0;
    while (n[i] && i < cap - 1) {
        name_out[i] = n[i];
        i++;
    }
    name_out[i] = '\0';
    return 0;
}

static vfs_node_t *tmpfs_create_child(vfs_node_t *node, const char *name, uint32_t flags)
{
    tnode_t *t = (tnode_t *)node;
    if (t->nchild >= TMPFS_MAX_CHILDREN)
        return NULL;
    tnode_t *child = new_node(name, flags);
    if (!child)
        return NULL;
    t->children[t->nchild++] = child;
    return &child->v;
}

static vfs_ops_t tmpfs_ops = {
    .read    = tmpfs_read,
    .write   = tmpfs_write,
    .finddir = tmpfs_finddir,
    .readdir = tmpfs_readdir,
    .create  = tmpfs_create_child,
};

vfs_node_t *tmpfs_create(void)
{
    tnode_t *root = new_node("/", VFS_DIR);
    return root ? &root->v : NULL;
}
