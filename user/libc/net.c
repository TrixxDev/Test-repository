/* AuroraOS libc: loopback socket connection setup (Phase 8A.2).
 *
 * socket()/send()/recv()/poll()/close() are thin syscalls (see libc.h). The
 * connection-setup calls below are RPCs to the netd broker over message IPC:
 * bind/listen/connect/accept never touch the kernel's port logic, because there
 * is none — the port namespace and rendezvous live entirely in netd.
 */
#include "libc.h"
#include "net.h"

/* Send a request to netd and wait for its reply (ignoring any stray messages
 * from other senders). Returns rep.status, or -1 if netd is unreachable. */
static int net_rpc(net_req_t *req, net_rep_t *rep)
{
    int np = svc_lookup(NET_SERVICE);
    if (np < 0)
        return -1;
    if (msgsend(np, req, sizeof(*req)) != 0)
        return -1;
    for (;;) {
        int from = -1;
        int n = msgrecv(rep, sizeof(*rep), &from);
        if (n < 0)
            return -1;
        if (from == np)
            return rep->status;
    }
}

int bind(int fd, int port)
{
    net_req_t req = { NET_BIND, port, fd };
    net_rep_t rep;
    return net_rpc(&req, &rep);
}

int listen(int fd)
{
    /* For loopback, bind already claims the port; nothing more is needed. The
     * call is kept so server code reads like the familiar socket lifecycle. */
    (void)fd;
    return 0;
}

int connect(int fd, int port)
{
    net_req_t req = { NET_CONNECT, port, fd };
    net_rep_t rep;
    return net_rpc(&req, &rep);
}

/* Create a fresh endpoint, offer it to netd for `port`, and block until a
 * client is matched to it. Returns the connected fd, or -1. */
int accept(int port)
{
    int c = socket(AF_LOOPBACK, SOCK_STREAM);
    if (c < 0)
        return -1;
    net_req_t req = { NET_ACCEPT, port, c };
    net_rep_t rep;
    if (net_rpc(&req, &rep) != 0) {
        close(c);
        return -1;
    }
    return c;
}
