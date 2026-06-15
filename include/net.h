/* AuroraOS loopback networking — userspace protocol (Phase 8A.2).
 *
 * The socket "stack" is the netd daemon, not the kernel. bind/listen/connect/
 * accept are libc calls that turn into message-passing RPCs to netd (found in
 * the service registry under NET_SERVICE). netd owns the AF_LOOPBACK port
 * namespace and brokers connections; it then asks the kernel to join the two
 * endpoints with sock_link(), after which data flows endpoint-to-endpoint.
 *
 * This header is the wire contract shared by netd and the libc socket calls.
 */
#pragma once
#include "syscall_abi.h"

#define NET_SERVICE "net"       /* registry name of the broker */

/* Request opcodes (client/server -> netd). */
enum {
    NET_BIND = 1,   /* server: claim a port                          */
    NET_ACCEPT,     /* server: offer a fresh endpoint for a client   */
    NET_CONNECT,    /* client: connect an endpoint to a bound port   */
};

typedef struct {
    int op;
    int port;
    int fd;         /* requester's socket fd (its half of the handle) */
} net_req_t;

typedef struct {
    int status;     /* 0 = ok, <0 = error      */
    int port;
    int peer_pid;   /* informational           */
} net_rep_t;

/* Ports below PORT_PRIVILEGED may only be bound by root (uid 0). */
#define PORT_PRIVILEGED 1024

/* The echo demo uses an unprivileged port so the uid-1000 server can bind it. */
#define PORT_ECHO 7000
