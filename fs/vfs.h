/* Virtual File System: a thin abstraction over concrete filesystems.
 *
 * A filesystem provides a tree of vfs_node_t objects and a vfs_ops_t table.
 * Filesystems are attached at mount points; path lookups pick the mount with
 * the longest matching prefix and then walk components via finddir(). */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define VFS_FILE 0x01
#define VFS_DIR  0x02

struct vfs_node;

typedef struct vfs_ops {
    int (*read)(struct vfs_node *node, uint32_t off, uint32_t size, uint8_t *buf);
    int (*write)(struct vfs_node *node, uint32_t off, uint32_t size, const uint8_t *buf);
    struct vfs_node *(*finddir)(struct vfs_node *node, const char *name);
    int (*readdir)(struct vfs_node *node, uint32_t index, char *name_out, uint32_t cap);
    struct vfs_node *(*create)(struct vfs_node *node, const char *name, uint32_t flags);
} vfs_ops_t;

typedef struct vfs_node {
    char     name[64];
    uint32_t flags;     /* VFS_FILE / VFS_DIR */
    uint32_t size;      /* bytes (files) */
    uint32_t inode;     /* fs-specific id (e.g. FAT first cluster) */
    vfs_ops_t *ops;
    void    *priv;      /* fs-specific data */
} vfs_node_t;

void vfs_init(void);

/* Attach `root` (a directory node) at the absolute path `path` ("/", "/disk"). */
int vfs_mount(const char *path, vfs_node_t *root);

/* Resolve an absolute path to a node, or NULL if not found. */
vfs_node_t *vfs_resolve(const char *path);

int vfs_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf);
int vfs_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf);
int vfs_readdir(vfs_node_t *node, uint32_t index, char *name_out, uint32_t cap);
vfs_node_t *vfs_finddir(vfs_node_t *node, const char *name);
vfs_node_t *vfs_create(vfs_node_t *dir, const char *name, uint32_t flags);
