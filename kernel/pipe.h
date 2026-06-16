/* Anonymous pipes: a kernel ring buffer with separate read/write VFS nodes. */
#pragma once
#include "vfs.h"

/* Create a pipe; returns its read node in *rnode and write node in *wnode. */
int pipe_create(vfs_node_t **rnode, vfs_node_t **wnode);

/* Drop a reference to one end (is_write = 1 for the write end). Frees the pipe
 * once both ends are fully closed. */
void pipe_close_end(vfs_node_t *node, int is_write);
