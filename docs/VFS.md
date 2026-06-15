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

A filesystem only implements the ops it supports (e.g. FAT32 is read-only and
has no `write`/`create`).

## Mounts and path resolution

- `vfs_mount(path, root_node)` attaches a filesystem root at an absolute path
  (e.g. `/`, `/disk`, `/tmp`).
- `vfs_resolve(path)` selects the mount with the longest matching prefix, then
  walks the remaining components with `finddir`.

## Filesystems

| Mount    | Filesystem | Backing            | Capabilities          |
|----------|------------|--------------------|-----------------------|
| `/tmp`   | tmpfs (`fs/tmpfs.c`) | kernel heap   | read/write/create/readdir |
| `/disk`  | FAT32 (`fs/fat32.c`) | ATA PIO disk  | read/finddir/readdir (read-only) |
| (device) | console (`drivers/console.c`) | keyboard + VGA | read (stdin) / write (stdout) |

- **tmpfs**: in-memory nodes; files grow on write.
- **FAT32**: parses the BPB, follows cluster chains, reads 8.3 directory
  entries; sits on the ATA PIO driver (`drivers/ata.c`).
- **console**: a single device node used for the standard streams.

## File descriptors

The process fd table maps small integers to open files
(`file_t { node, offset, refcount, role }`). `open` resolves a path to a node
and installs a descriptor; `read`/`write` advance the offset. See
[PROCESS_MODEL.md](PROCESS_MODEL.md) and [IPC.md](IPC.md) (pipes are also
descriptors).

## Limitations / TODO

- No write support for FAT32, no block cache, no permissions/ownership.
- No path normalization for `.`/`..`.
