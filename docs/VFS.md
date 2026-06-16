# AuroraOS Virtual File System

The VFS (`fs/vfs.c`) is a thin abstraction over concrete filesystems. A
filesystem provides a tree of `vfs_node_t` objects plus an operations table;
filesystems are attached at mount points.

## Node and operations

```
vfs_node_t {
    name[64]
    flags        // VFS_FILE | VFS_DIR
    size
    inode        // fs-specific id (e.g. FAT first cluster)
    mode         // permission bits, Unix rwxrwxrwx (low 9 bits)
    owner_uid    // owning uid (0 = root)
    ops          // vfs_ops_t *
    priv         // fs-specific data
}

vfs_ops_t {
    read(node, off, size, buf)
    write(node, off, size, buf)
    finddir(node, name) -> node
    readdir(node, index, name_out, cap)
    create(node, name, flags) -> node
}
```

A filesystem only implements the ops it supports.

## Mounts and path resolution

- `vfs_mount(path, root_node)` attaches a filesystem root at an absolute path
  (e.g. `/`, `/disk`, `/tmp`).
- `vfs_resolve(path)` selects the mount with the longest matching prefix, then
  walks the remaining components with `finddir`.

## Filesystems

| Mount    | Filesystem | Backing            | Capabilities          |
|----------|------------|--------------------|-----------------------|
| `/tmp`   | tmpfs (`fs/tmpfs.c`) | kernel heap   | read/write/create/readdir |
| `/disk`  | FAT32 (`fs/fat32.c`) | ATA PIO disk  | read/write/create/finddir/readdir |
| (device) | console (`drivers/console.c`) | keyboard + VGA | read (stdin) / write (stdout) |

- **tmpfs**: in-memory nodes; files grow on write.
- **FAT32**: parses the BPB, follows cluster chains, reads/writes 8.3 entries.
  Writes go through `drivers/ata.c` (`ata_write_sectors` + cache flush):
  `create` makes a root-directory entry, `write` allocates clusters and grows
  the chain (read-modify-writing partial clusters), and the file's size + first
  cluster are written back to its directory entry in **both** FAT copies.
- **console**: a single device node used for the standard streams.

## Permissions (Phase 8A.5)

Each node carries an `owner_uid` and a Unix-style `mode` (rwx for owner / rwx
for other — no group yet). `vfs_permitted(node, uid, want)` decides access:
root (uid 0) always passes; otherwise the owner bits apply to the owner and the
"other" bits to everyone else.

Enforcement happens at **path open time**, not per read/write (a descriptor is a
capability once obtained, as in Unix):

- `open(path, flags)` checks `VFS_R`/`VFS_W` according to the access mode
  (`O_RDONLY`/`O_WRONLY`/`O_RDWR`). With `O_CREAT`, the file is created if absent
  — which checks `VFS_W` on the **parent directory** and makes the new file owned
  by the caller (mode `0644`). `O_TRUNC` resets the length to zero.
- `exec(path)` checks `VFS_X`.

Pipes, sockets and the console are installed as descriptors directly (never via a
path), so they are not permission-checked at open.

Defaults by filesystem:

| Source   | owner | mode | rationale |
|----------|-------|------|-----------|
| tmpfs file | 0 (creator) | `0644` | readable by all, writable by owner |
| tmpfs dir  | 0 (creator) | `0755` | traversable by all |
| FAT32 (any) | 0 | `0755` | read-only medium; world read+exec |
| console    | 0 | `0666` | shared terminal, rw for all |

## File descriptors

The process fd table maps small integers to open files
(`file_t { node, offset, refcount, role }`). `open` resolves a path to a node,
checks permissions, and installs a descriptor; `read`/`write` advance the
offset. See [PROCESS_MODEL.md](PROCESS_MODEL.md) and [IPC.md](IPC.md) (pipes and
sockets are also descriptors).

## Limitations / TODO

- FAT32 write covers create/grow/overwrite/truncate of files in the **root
  directory**. Not yet: file delete, freeing clusters on truncate (the tail of
  the chain leaks), subdirectory creation, and a block cache (every op hits the
  disk).
- Permissions have no group bits, and FAT32 perms are synthetic (`0755` files /
  `0777` dirs, root-owned) so they reset on remount; a metadata-carrying FS would
  persist real owner/mode.
- No path normalization for `.`/`..`.
