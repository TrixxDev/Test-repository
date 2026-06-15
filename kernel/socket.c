/* AuroraOS socket layer (Phase 8A.1) — see socket.h.
 *
 * A connected pair shares one sock_conn_t holding two independent ring buffers
 * (one per direction), mirroring the blocking/wake discipline of kernel/pipe.c.
 * The shared object outlives either endpoint and is freed only once both ends
 * close, so there is never a dangling peer pointer.
 */
#include "socket.h"
#include "scheduler.h"
#include "kheap.h"
#include "string.h"
#include "process.h"

#define SOCK_BUF 2048

typedef struct {
    uint8_t buf[SOCK_BUF];
    int     head, tail, count;
} ring_t;

typedef struct sock_conn {
    ring_t    to[2];        /* to[s] = bytes destined for side s (its inbound) */
    int       open[2];      /* open[s] = side s endpoint still open            */
    thread_t *rwait[2];     /* side s blocked reading its inbound (to[s])      */
    thread_t *wwait[2];     /* side s blocked writing (space in to[1-s])       */
    thread_t *pwait[2];     /* side s blocked in poll()                        */
} sock_conn_t;

enum { SS_NEW = 0, SS_CONNECTED, SS_LISTENING };

typedef struct socket {
    int          domain, type, state;
    sock_conn_t *conn;      /* NULL until linked */
    int          side;      /* 0 = 'a', 1 = 'b'  */
    int          refs;
    vfs_node_t  *node;
} socket_t;

/* ---- ring helpers (caller holds interrupts off) ---- */

static int ring_get(ring_t *r, uint8_t *out, int max)
{
    int n = 0;
    while (n < max && r->count > 0) {
        out[n++] = r->buf[r->head];
        r->head = (r->head + 1) % SOCK_BUF;
        r->count--;
    }
    return n;
}

static int ring_put(ring_t *r, const uint8_t *in, int max)
{
    int n = 0;
    while (n < max && r->count < SOCK_BUF) {
        r->buf[r->tail] = in[n++];
        r->tail = (r->tail + 1) % SOCK_BUF;
        r->count++;
    }
    return n;
}

static void wake(thread_t **slot)
{
    if (*slot) {
        thread_wake(*slot);
        *slot = NULL;
    }
}

/* ---- VFS ops: read == recv, write == send ---- */

static int sock_node_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *out)
{
    (void)off;
    socket_t *s = (socket_t *)node->priv;
    if (!s->conn)
        return -1;                          /* not connected */
    sock_conn_t *c = s->conn;
    int sd = s->side, peer = 1 - sd;

    __asm__ volatile("cli");
    while (c->to[sd].count == 0 && c->open[peer]) {
        c->rwait[sd] = thread_current();
        thread_block();
    }
    int n = ring_get(&c->to[sd], out, (int)size);
    if (n > 0) {
        wake(&c->wwait[peer]);              /* peer can write more into to[sd] */
        wake(&c->pwait[peer]);              /* peer poller waiting on POLLOUT  */
    }
    __asm__ volatile("sti");
    return n;                               /* 0 == EOF (peer closed, drained) */
}

static int sock_node_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *in)
{
    (void)off;
    socket_t *s = (socket_t *)node->priv;
    if (!s->conn)
        return -1;
    sock_conn_t *c = s->conn;
    int sd = s->side, peer = 1 - sd;
    int n = 0;

    __asm__ volatile("cli");
    while (n < (int)size) {
        if (!c->open[peer]) {               /* peer gone -> broken connection */
            __asm__ volatile("sti");
            return n ? n : -1;
        }
        while (c->to[peer].count == SOCK_BUF && c->open[peer]) {
            c->wwait[sd] = thread_current();
            thread_block();
        }
        if (!c->open[peer])
            continue;
        n += ring_put(&c->to[peer], in + n, (int)size - n);
        wake(&c->rwait[peer]);              /* peer reader waiting on POLLIN */
        wake(&c->pwait[peer]);
    }
    __asm__ volatile("sti");
    return n;
}

static vfs_ops_t sock_ops = { .read = sock_node_read, .write = sock_node_write };

int sock_is_socket(vfs_node_t *node)
{
    return node && node->ops == &sock_ops;
}

/* ---- lifecycle ---- */

vfs_node_t *sock_create(int domain, int type)
{
    if (domain != AF_LOOPBACK || type != SOCK_STREAM)
        return NULL;
    socket_t   *s = (socket_t *)kmalloc(sizeof(socket_t));
    vfs_node_t *n = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!s || !n) {
        kfree(s);
        kfree(n);
        return NULL;
    }
    memset(s, 0, sizeof(*s));
    memset(n, 0, sizeof(*n));
    s->domain = domain;
    s->type   = type;
    s->state  = SS_NEW;
    s->refs   = 1;
    s->node   = n;
    n->flags  = VFS_FILE;
    n->ops    = &sock_ops;
    n->priv   = s;
    memcpy(n->name, "socket", 7);
    return n;
}

void sock_close(vfs_node_t *node)
{
    socket_t *s = (socket_t *)node->priv;
    if (--s->refs > 0)
        return;

    sock_conn_t *c = s->conn;
    int free_conn = 0;
    if (c) {
        int sd = s->side, peer = 1 - sd;
        __asm__ volatile("cli");
        c->open[sd] = 0;
        wake(&c->rwait[peer]);              /* peer recv -> EOF   */
        wake(&c->wwait[peer]);              /* peer send -> broken */
        wake(&c->pwait[peer]);
        free_conn = (!c->open[0] && !c->open[1]);
        __asm__ volatile("sti");
    }
    kfree(s);
    kfree(node);
    if (free_conn)
        kfree(c);
}

int sock_link(uint32_t handle_a, uint32_t handle_b)
{
    vfs_node_t *na = proc_socket_node(SOCK_HANDLE_PID(handle_a), SOCK_HANDLE_FD(handle_a));
    vfs_node_t *nb = proc_socket_node(SOCK_HANDLE_PID(handle_b), SOCK_HANDLE_FD(handle_b));
    if (!na || !nb || na == nb)
        return -1;
    socket_t *sa = (socket_t *)na->priv;
    socket_t *sb = (socket_t *)nb->priv;
    if (sa->conn || sb->conn)
        return -1;                          /* already connected */

    sock_conn_t *c = (sock_conn_t *)kmalloc(sizeof(sock_conn_t));
    if (!c)
        return -1;
    memset(c, 0, sizeof(*c));
    c->open[0] = c->open[1] = 1;
    sa->conn = c; sa->side = 0; sa->state = SS_CONNECTED;
    sb->conn = c; sb->side = 1; sb->state = SS_CONNECTED;
    return 0;
}

/* ---- poll support (caller holds interrupts off) ---- */

int sock_poll(vfs_node_t *node, int events)
{
    socket_t *s = (socket_t *)node->priv;
    sock_conn_t *c = s->conn;
    if (!c)
        return POLLERR;                     /* unconnected: never blocks poll */

    int sd = s->side, peer = 1 - sd;
    int re = 0;
    if ((events & POLLIN) && (c->to[sd].count > 0 || !c->open[peer]))
        re |= POLLIN;
    if ((events & POLLOUT) && c->open[peer] && c->to[peer].count < SOCK_BUF)
        re |= POLLOUT;
    if (!c->open[peer])
        re |= POLLERR;
    return re;
}

void sock_poll_arm(vfs_node_t *node, thread_t *t)
{
    socket_t *s = (socket_t *)node->priv;
    if (s->conn)
        s->conn->pwait[s->side] = t;
}

void sock_poll_disarm(vfs_node_t *node, thread_t *t)
{
    socket_t *s = (socket_t *)node->priv;
    if (s->conn && s->conn->pwait[s->side] == t)
        s->conn->pwait[s->side] = 0;
}
