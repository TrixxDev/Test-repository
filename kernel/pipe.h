/* Anonymous pipes: a kernel ring buffer with separate read/write VFS nodes. */
#pragma once
#include "vfs.h"
#include "scheduler.h"      /* wait_queue_t */

/* Create a pipe; returns its read node in *rnode and write node in *wnode. */
int pipe_create(vfs_node_t **rnode, vfs_node_t **wnode);

/* Drop a reference to one end (is_write = 1 for the write end). Frees the pipe
 * once both ends are fully closed. */
void pipe_close_end(vfs_node_t *node, int is_write);

/* Phase 18.3: readiness for wait_events()/poll(). Call with interrupts
 * disabled. */
int pipe_poll(vfs_node_t *node, int events);

/* The wait queue this end (read or write) of the pipe blocks on. */
wait_queue_t *pipe_waitq(vfs_node_t *node);
