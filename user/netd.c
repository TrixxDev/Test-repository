/* netd: the AuroraOS loopback network daemon (Phase 8A.2).
 *
 * netd is the socket "stack": it owns the AF_LOOPBACK port namespace and brokers
 * connections. Servers bind a port and offer fresh endpoints (accept); clients
 * connect to a port. When a client and a server endpoint meet, netd joins them
 * with the privileged sock_link() syscall (allowed because netd runs as root),
 * then data flows endpoint-to-endpoint without passing back through netd.
 *
 * All requests arrive as message-passing RPCs (see include/net.h); netd never
 * blocks on the kernel — it only ever replies once a rendezvous completes.
 */
#include "libc.h"
#include "net.h"

#define MAX_PORTS 8
#define MAX_PEND  8

typedef struct { int used; int port; int pid; } bound_t;
typedef struct { int used; int port; int pid; int fd; } pend_t;

static bound_t bound[MAX_PORTS];
static pend_t  accepts[MAX_PEND];    /* server endpoints waiting for a client */
static pend_t  connects[MAX_PEND];   /* client endpoints waiting for a server */

static int port_bound(int port)
{
    for (int i = 0; i < MAX_PORTS; i++)
        if (bound[i].used && bound[i].port == port)
            return 1;
    return 0;
}

static int add_bound(int port, int pid)
{
    for (int i = 0; i < MAX_PORTS; i++)
        if (bound[i].used && bound[i].port == port) { bound[i].pid = pid; return 0; }
    for (int i = 0; i < MAX_PORTS; i++)
        if (!bound[i].used) { bound[i].used = 1; bound[i].port = port; bound[i].pid = pid; return 0; }
    return -1;
}

static int take_pending(pend_t *q, int port, int *pid, int *fd)
{
    for (int i = 0; i < MAX_PEND; i++)
        if (q[i].used && q[i].port == port) {
            *pid = q[i].pid; *fd = q[i].fd; q[i].used = 0;
            return 1;
        }
    return 0;
}

static int add_pending(pend_t *q, int port, int pid, int fd)
{
    for (int i = 0; i < MAX_PEND; i++)
        if (!q[i].used) { q[i].used = 1; q[i].port = port; q[i].pid = pid; q[i].fd = fd; return 0; }
    return -1;
}

static void reply(int pid, int status, int port, int peer)
{
    net_rep_t rep = { status, port, peer };
    msgsend(pid, &rep, sizeof(rep));
}

/* Join a client endpoint and a server endpoint, then unblock both sides. */
static void do_match(int cli_pid, int cli_fd, int srv_pid, int srv_fd, int port)
{
    int r = sock_link(SOCK_HANDLE(cli_pid, cli_fd), SOCK_HANDLE(srv_pid, srv_fd));
    reply(cli_pid, r, port, srv_pid);
    reply(srv_pid, r, port, cli_pid);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (svc_register(NET_SERVICE) != 0) {
        fprintf(2, "netd: failed to register\n");
        return 1;
    }
    printf("[netd] ready (pid %d, uid %d), registered as \"%s\"\n",
           getpid(), getuid(), NET_SERVICE);

    for (;;) {
        net_req_t req;
        int from = -1;
        int n = msgrecv(&req, sizeof(req), &from);
        if (n < (int)sizeof(req))
            continue;

        switch (req.op) {
        case NET_BIND:
            /* Privileged ports (< 1024) are reserved for root. The uid comes
             * from the kernel (uid_of), not the request, so it can't be forged. */
            if (req.port < PORT_PRIVILEGED && uid_of(from) != 0)
                reply(from, -1, req.port, 0);
            else
                reply(from, add_bound(req.port, from), req.port, 0);
            break;

        case NET_ACCEPT: {
            int cpid, cfd;
            if (take_pending(connects, req.port, &cpid, &cfd))
                do_match(cpid, cfd, from, req.fd, req.port);
            else if (add_pending(accepts, req.port, from, req.fd) != 0)
                reply(from, -1, req.port, 0);   /* queue full */
            /* else: the server blocks until a client connects */
            break;
        }

        case NET_CONNECT: {
            if (!port_bound(req.port)) { reply(from, -1, req.port, 0); break; }
            int spid, sfd;
            if (take_pending(accepts, req.port, &spid, &sfd))
                do_match(from, req.fd, spid, sfd, req.port);
            else if (add_pending(connects, req.port, from, req.fd) != 0)
                reply(from, -1, req.port, 0);   /* queue full */
            /* else: the client blocks until the server accepts */
            break;
        }

        default:
            reply(from, -1, 0, 0);
            break;
        }
    }
    return 0;
}
