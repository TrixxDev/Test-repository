/* INET stream sockets (AF_INET / SOCK_STREAM) as VFS-node-backed file
 * descriptors. A socket fd's read == recv and write == send, exactly like the
 * loopback sockets, but the backend is the real TCP stack. This is the clean
 * boundary the user-space HTTP client (and, later, TLS) sits on top of, instead
 * of reaching into TCP internals. */
#pragma once
#include "vfs.h"
#include "scheduler.h"      /* wait_queue_t */

/* Create an unconnected TCP socket node (priv = connection handle, -1). */
vfs_node_t *tcpsock_create(void);

/* 1 if `node` is a TCP socket (vs a loopback socket or a file). */
int  tcpsock_is(vfs_node_t *node);

/* Resolve `host` and open a connection to host:port. Returns 0 on success,
 * -2 (DNS failed) or -3 (connect failed). Must run with interrupts enabled. */
int  tcpsock_connect(vfs_node_t *node, const char *host, int port);

/* Close the connection and free the node. */
void tcpsock_close(vfs_node_t *node);

/* Phase 18.3: readiness for wait_events()/poll(). Call with interrupts
 * disabled. */
int  tcpsock_poll(vfs_node_t *node, int events);

/* The wait queue this socket blocks on (both directions share one). */
wait_queue_t *tcpsock_waitq(vfs_node_t *node);
