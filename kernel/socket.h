/* AuroraOS socket layer — the kernel "network object" (Phase 8A.1).
 *
 * This is pure mechanism, no policy: a socket is a connectable, bidirectional
 * byte-stream endpoint backed by a VFS node (so it lives in the fd table and
 * works with read/write/close/poll like any other descriptor). The kernel does
 * NOT know about ports, addresses or protocols — that "stack" lives in the
 * userspace netd daemon, which joins two endpoints with sock_link().
 *
 * Only AF_LOOPBACK / SOCK_STREAM is supported: an in-machine connection between
 * two endpoints, with no driver or hardware involved.
 */
#pragma once
#include <stdint.h>
#include "vfs.h"
#include "syscall_abi.h"

/* Create an unconnected socket endpoint. Returns its VFS node, or NULL. */
vfs_node_t *sock_create(int domain, int type);

/* Drop one fd reference to a socket node; tears the endpoint (and, once both
 * ends are closed, the shared connection) down on the last reference. */
void sock_close(vfs_node_t *node);

/* Join two unconnected endpoints into a connected pair. Each argument is a
 * packed (pid, fd) handle (see SOCK_HANDLE). Used by the netd broker; returns
 * 0 on success, -1 if either handle is not an unconnected socket. */
int sock_link(uint32_t handle_a, uint32_t handle_b);

/* Readiness query for poll(): returns the subset of POLLIN/POLLOUT/POLLERR
 * that currently holds for this socket node. Call with interrupts disabled. */
int sock_poll(vfs_node_t *node, int events);

/* Register/clear the current thread as the poll waiter for a socket so a peer
 * send/recv/close wakes it. Call with interrupts disabled. */
struct thread;
void sock_poll_arm(vfs_node_t *node, struct thread *t);
void sock_poll_disarm(vfs_node_t *node, struct thread *t);

/* True if `node` is a socket endpoint (used by the fd layer / poll). */
int sock_is_socket(vfs_node_t *node);
