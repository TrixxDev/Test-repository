/* INET stream sockets over the TCP stack — see tcpsock.h. */
#include "tcpsock.h"
#include "tcp.h"
#include "netstack.h"
#include "dns.h"
#include "inet.h"
#include "kheap.h"
#include "string.h"
#include "scheduler.h"

#define TCPSOCK_MSS 1400

struct tcpsock { int h; };      /* TCP connection handle, -1 until connected */

static int tsk_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *out);
static int tsk_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *in);

static vfs_ops_t tcpsock_ops = { .read = tsk_read, .write = tsk_write };

int tcpsock_is(vfs_node_t *node) { return node && node->ops == &tcpsock_ops; }

/* Parse a dotted-quad "a.b.c.d" into a host-order IPv4 address (a in the high
 * byte, matching dns_query / the IP4 macro). Returns 1 on a complete, valid
 * literal, else 0 so the caller falls back to a DNS lookup. Lets a program
 * connect straight to a numeric address (e.g. the QEMU host at 10.0.2.2) when no
 * resolver knows the name. */
static int parse_ipv4(const char *s, uint32_t *out)
{
    uint32_t ip = 0;
    for (int part = 0; part < 4; part++) {
        if (*s < '0' || *s > '9') return 0;
        int v = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); if (v > 255) return 0; s++; }
        ip = (ip << 8) | (uint32_t)v;
        if (part < 3 && *s++ != '.') return 0;
    }
    if (*s != '\0') return 0;
    *out = ip;
    return 1;
}

vfs_node_t *tcpsock_create(void)
{
    struct tcpsock *t = (struct tcpsock *)kmalloc(sizeof(*t));
    vfs_node_t     *n = (vfs_node_t *)kmalloc(sizeof(*n));
    if (!t || !n) { kfree(t); kfree(n); return NULL; }
    memset(t, 0, sizeof(*t));
    memset(n, 0, sizeof(*n));
    t->h     = -1;
    n->flags = VFS_FILE;
    n->mode  = 0600;
    n->ops   = &tcpsock_ops;
    n->priv  = t;
    memcpy(n->name, "tcpsock", 8);
    return n;
}

int tcpsock_connect(vfs_node_t *node, const char *host, int port)
{
    struct tcpsock *t = (struct tcpsock *)node->priv;
    uint32_t ip;
    if (!parse_ipv4(host, &ip)) {               /* a numeric host skips DNS */
        if (dns_query(host, DNS_A, &ip) != 0)
            return -2;                          /* DNS failed */
    }
    int h = tcp_connect(ip, (uint16_t)port);
    if (h < 0)
        return -3;
    uint64_t dl = net_now_ms() + 5000;
    while (net_now_ms() < dl &&
           tcp_state(h) != TCP_ESTABLISHED && tcp_state(h) != TCP_CLOSED)
        net_poll();
    if (tcp_state(h) != TCP_ESTABLISHED)
        return -3;                              /* connect failed / refused */
    t->h = h;
    return 0;
}

void tcpsock_close(vfs_node_t *node)
{
    struct tcpsock *t = (struct tcpsock *)node->priv;
    if (t) {
        if (t->h >= 0) {
            /* The teardown poll loop is timed by net_now_ms(), which only advances
             * while the PIT ticks. close() and process exit reach here through the
             * interrupt-gated (IRQs-off) syscall path, so without enabling IRQs the
             * clock is frozen, the 1.5s deadline never fires, and a peer that is
             * slow to finish the FIN handshake wedges the loop forever (hanging the
             * whole machine, since with IRQs off nothing can preempt it). Enable
             * IRQs for the wait, then restore the caller's flag -- process_exit
             * relies on IRQs staying off through its later address-space teardown. */
            uint32_t fl;
            __asm__ volatile("pushf; pop %0" : "=r"(fl));
            __asm__ volatile("sti");
            tcp_close(t->h);
            uint64_t dl = net_now_ms() + 1500;
            while (net_now_ms() < dl && tcp_state(t->h) != TCP_CLOSED)
                net_poll();
            if (!(fl & 0x200))
                __asm__ volatile("cli");
        }
        kfree(t);
    }
    kfree(node);
}

/* recv: block until data arrives, the peer closes (EOF -> 0), or the idle
 * timeout elapses.
 *
 * Phase 17.5.2 raised the idle timeout from 10s to 60s: large-response
 * stress testing found a real bug here, not just a size limit. A read()
 * returning 0 is indistinguishable to every caller from a genuine peer
 * close (see e.g. user/httpsget.c's h2_fetch(), which folds both into
 * "connection closed" and quietly accepts whatever body arrived so far as
 * the complete response) -- but this function was declaring that same 0
 * after a mere 10 seconds of no NEW bytes on a connection that was still
 * fully TCP_ESTABLISHED, wrongly turning "still connected, just slow right
 * now" into a silently truncated response. A 1 MB transfer over Aurora's
 * own from-scratch TLS record decryption reproduced this reliably even
 * though the peer never stopped sending and the connection never actually
 * closed. 60s is still a real backstop against a truly wedged peer -- just
 * one that no longer fires during ordinary large-response traffic.
 *
 * Phase 18.1.5: this used to busy-spin calling net_poll() every iteration
 * with no yield at all, since Aurora's network stack is cooperatively
 * polled (net_poll() dispatches RX only when something explicitly calls it
 * -- the virtio-net IRQ handler just acks the device, see drivers/virtio_net.c),
 * not interrupt-driven. Blocking on the connection's own wait queue between
 * attempts, with a short timeout, removes this thread from the scheduler's
 * run queue entirely instead of burning its whole time slice every round --
 * tcp_input() also wakes it early (a latency win, not a correctness
 * requirement) whenever a DIFFERENT thread's net_poll() happens to deliver
 * data for this connection first. */
static int tsk_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *out)
{
    (void)off;
    struct tcpsock *t = (struct tcpsock *)node->priv;
    if (!t || t->h < 0)
        return -1;
    wait_queue_t *wq = tcp_conn_waitq(t->h);
    __asm__ volatile("sti");
    uint64_t dl = net_now_ms() + 60000;
    for (;;) {
        net_poll();
        int g = tcp_recv(t->h, out, size);
        if (g > 0)
            return g;
        int st = tcp_state(t->h);
        if (st == TCP_CLOSE_WAIT || st == TCP_LAST_ACK || st == TCP_CLOSING ||
            st == TCP_TIME_WAIT || st == TCP_CLOSED)
            return 0;                           /* peer closed and drained -> EOF */
        if (net_now_ms() >= dl)
            return 0;                           /* idle timeout -> EOF */
        __asm__ volatile("cli");
        if (wq)
            wait_event_timeout(wq, 20);          /* short poll interval, may wake early */
        __asm__ volatile("sti");
    }
}

/* send: transmit in MSS-sized segments, stop-and-wait (one outstanding segment
 * under the single-segment retransmit cache). */
static int tsk_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *in)
{
    (void)off;
    struct tcpsock *t = (struct tcpsock *)node->priv;
    if (!t || t->h < 0 || tcp_state(t->h) != TCP_ESTABLISHED)
        return -1;
    __asm__ volatile("sti");
    unsigned sent = 0;
    while (sent < size) {
        unsigned chunk = size - sent;
        if (chunk > TCPSOCK_MSS) chunk = TCPSOCK_MSS;
        int r = tcp_send(t->h, in + sent, chunk);
        if (r <= 0)
            break;
        sent += (unsigned)r;
        uint64_t dl = net_now_ms() + 4000;      /* wait for the ACK before the next */
        while (net_now_ms() < dl && !tcp_tx_idle(t->h))
            net_poll();
    }
    return sent ? (int)sent : -1;
}
