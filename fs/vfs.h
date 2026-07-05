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

/* Permission bits (used against a node's `mode`, Unix rwx semantics). */
#define VFS_R 0x4
#define VFS_W 0x2
#define VFS_X 0x1

struct vfs_node;

typedef struct vfs_ops {
    /* `flags` is the calling fd's own status flags (O_NONBLOCK, Phase 18.2) --
     * a property of the open file description, not of `node` (two fds can
     * share one node with different blocking behavior), so it can't live on
     * vfs_node_t itself and must be threaded through here. Most
     * implementations (regular files) ignore it; console/pipe/socket honor it. */
    int (*read)(struct vfs_node *node, uint32_t off, uint32_t size, uint8_t *buf, int flags);
    int (*write)(struct vfs_node *node, uint32_t off, uint32_t size, const uint8_t *buf, int flags);
    struct vfs_node *(*finddir)(struct vfs_node *node, const char *name);
    int (*readdir)(struct vfs_node *node, uint32_t index, char *name_out, uint32_t cap);
    struct vfs_node *(*create)(struct vfs_node *node, const char *name, uint32_t flags);
} vfs_ops_t;

typedef struct vfs_node {
    char     name[64];
    uint32_t flags;     /* VFS_FILE / VFS_DIR */
    uint32_t size;      /* bytes (files) */
    uint32_t inode;     /* fs-specific id (e.g. FAT first cluster) */
    uint32_t mode;      /* permission bits, Unix-style rwxrwxrwx (low 9 bits) */
    int      owner_uid; /* owning uid (0 = root) */
    vfs_ops_t *ops;
    void    *priv;      /* fs-specific data */
} vfs_node_t;

void vfs_init(void);

/* Attach `root` (a directory node) at the absolute path `path` ("/", "/disk"). */
int vfs_mount(const char *path, vfs_node_t *root);

/* Resolve an absolute path to a node, or NULL if not found. */
vfs_node_t *vfs_resolve(const char *path);

/* Does `uid` have all of `want` (VFS_R/W/X) on `node`? Root (uid 0) always
 * passes; otherwise the owner bits apply to the owner and the "other" bits to
 * everyone else (no group concept yet). */
int vfs_permitted(vfs_node_t *node, int uid, int want);

int vfs_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf, int flags);
int vfs_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf, int flags);
int vfs_readdir(vfs_node_t *node, uint32_t index, char *name_out, uint32_t cap);
vfs_node_t *vfs_finddir(vfs_node_t *node, const char *name);
vfs_node_t *vfs_create(vfs_node_t *dir, const char *name, uint32_t flags);
