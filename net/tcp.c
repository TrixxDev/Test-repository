/* TCP client connections over a fixed connection table — see tcp.h. */
#include "tcp.h"
#include "rxring.h"
#include "ipv4.h"
#include "netstack.h"
#include "inet.h"
#include "perf.h"
#include "string.h"
#include "scheduler.h"

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;      /* high nibble = header length in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed));

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10

#define TCP_TX_MAX    1400          /* one segment, well under the MTU */
#define TCP_TIME_WAIT_MS 1000       /* shortened 2*MSL (real TCP: minutes) */
#define TCP_RTO_MS    1000          /* initial retransmit timeout (RFC 6298) */
#define TCP_RTO_MAX   8000          /* backoff cap */
#define TCP_MAX_RETX  5             /* give up after this many resends */
#define TCP_MAX_INFLIGHT 8          /* Phase 18.4.1: unacknowledged segments a
                                      * connection may have outstanding at once */
#define TCP_MAX_OOO      8          /* Phase 18.4.2: out-of-order segments held
                                      * pending the gap before them closing */
#define TCP_OOO_SEG_MAX  1480       /* generous single-segment cap (a common
                                      * peer MTU/MSS); a larger arrival is
                                      * dropped rather than held -- rare, and
                                      * the peer's own retransmit timer
                                      * recovers it same as today */

/* Phase 18.4.2: one segment that arrived ahead of what we've got
 * contiguously (seq > rcv_nxt) -- held instead of dropped, so the peer
 * doesn't have to blindly resend data we may already have once the gap
 * before it closes. */
struct ooo_seg {
    uint8_t   data[TCP_OOO_SEG_MAX];
    unsigned  len;
    uint32_t  seq;
    int       used;
};

/* Phase 18.4.1: one outstanding, sequence-consuming segment (SYN / data /
 * FIN) -- a pure ACK is never retransmitted. On RTO with no ACK, resent
 * (with a refreshed ack/window) and independently backed off; cleared once
 * a cumulative ACK covers its end sequence. `struct conn` keeps up to
 * TCP_MAX_INFLIGHT of these as a ring (oldest-unacked-first), replacing the
 * single-segment stop-and-wait model every write() used to be serialized
 * through. */
struct rtx {
    uint8_t   data[TCP_TX_MAX];
    unsigned  len;              /* payload bytes */
    uint8_t   flags;
    uint32_t  seq;
    int       used;
    uint64_t  last_ms;
    uint32_t  rto_ms;
    uint8_t   retries;
};

/* One connection: its control block plus the buffering/timer state the public
 * TCB shape doesn't carry. `used` slots that reach CLOSED are reused by the next
 * connect (kept around first so a caller can drain trailing data after close). */
struct conn {
    struct tcp_tcb tcb;
    rxring    rx;               /* in-order received data, drained by tcp_recv */
    unsigned  rx_total;         /* lifetime bytes accepted (for tcp_rx_total) */
    uint64_t  tw_deadline;      /* TIME_WAIT -> CLOSED moment */
    struct rtx rtx[TCP_MAX_INFLIGHT];  /* ring; rtx[rtx_head] is the oldest
                                         * unacked segment (ACKs are
                                         * cumulative, so they always clear
                                         * from the front) */
    int       rtx_head;         /* index of the oldest unacked segment */
    int       rtx_count;        /* how many of rtx[] are currently used */
    struct ooo_seg ooo[TCP_MAX_OOO];   /* Phase 18.4.2: held out-of-order arrivals */
    int       used;
    wait_queue_t rwq;           /* Phase 18.1.5: tsk_read() blocks here instead
                                  * of busy-spinning on net_poll(); woken (as a
                                  * latency optimization, not a correctness
                                  * requirement -- see tcp_input()) whenever a
                                  * segment changes anything a reader might
                                  * care about. Zero-initialized, same as the
                                  * rest of `conns[]`. */
};

static int test_drop_data;      /* test hook: drop the next data segment once */

static struct conn conns[TCP_MAX_CONN];
static struct tcp_stats stats;

void tcp_init(void)
{
    memset(conns, 0, sizeof(conns));
    memset(&stats, 0, sizeof(stats));
}

void tcp_get_stats(struct tcp_stats *out) { if (out) *out = stats; }

static struct conn *conn_of(int h)
{
    if (h < 0 || h >= TCP_MAX_CONN || !conns[h].used)
        return NULL;
    return &conns[h];
}

int tcp_state(int h)
{
    struct conn *c = conn_of(h);
    return c ? c->tcb.state : TCP_CLOSED;
}

const char *tcp_state_name(int s)
{
    switch (s) {
    case TCP_CLOSED:       return "CLOSED";
    case TCP_LISTEN:       return "LISTEN";
    case TCP_SYN_SENT:     return "SYN_SENT";
    case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
    case TCP_ESTABLISHED:  return "ESTABLISHED";
    case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
    case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
    case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_CLOSING:      return "CLOSING";
    case TCP_LAST_ACK:     return "LAST_ACK";
    case TCP_TIME_WAIT:    return "TIME_WAIT";
    default:               return "?";
    }
}

/* TCP checksum over the pseudo-header + segment, all interpreted as big-endian
 * 16-bit words (RFC 793). Used for both TX (field zeroed) and RX (verify == 0). */
static uint16_t tcp_checksum(uint32_t src, uint32_t dst,
                             const uint8_t *seg, unsigned len)
{
    uint32_t sum = 0;
    sum += (src >> 16) & 0xffff; sum += src & 0xffff;
    sum += (dst >> 16) & 0xffff; sum += dst & 0xffff;
    sum += IPPROTO_TCP;
    sum += len;
    for (unsigned i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t)seg[i] << 8) | seg[i + 1];
    if (len & 1)
        sum += (uint32_t)seg[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Send a segment for connection `c` with `flags`, optionally carrying payload. */
static int tcp_xmit(struct conn *c, uint8_t flags, uint32_t seq, uint32_t ack,
                    const void *data, unsigned len)
{
    static uint8_t buf[sizeof(struct tcp_hdr) + TCP_TX_MAX];
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;

    struct tcp_hdr *h = (struct tcp_hdr *)buf;
    h->src_port = htons(c->tcb.local_port);
    h->dst_port = htons(c->tcb.remote_port);
    h->seq      = htonl(seq);
    h->ack      = htonl(ack);
    h->data_off = 5 << 4;                       /* 20-byte header, no options */
    h->flags    = flags;
    h->window   = htons(c->tcb.rcv_wnd);
    h->checksum = 0;
    h->urg_ptr  = 0;
    if (len)
        memcpy(buf + sizeof(struct tcp_hdr), data, len);

    unsigned total = sizeof(struct tcp_hdr) + len;
    h->checksum = htons(tcp_checksum(c->tcb.local_ip, c->tcb.remote_ip, buf, total));
    return ipv4_send(c->tcb.remote_ip, IPPROTO_TCP, buf, total);
}

/* Sequence-consuming length of a segment (SYN and FIN each occupy one). */
static uint32_t seg_len(uint8_t flags, unsigned len)
{
    return len + ((flags & TCP_SYN) ? 1 : 0) + ((flags & TCP_FIN) ? 1 : 0);
}

/* Phase 18.4.1: appends a new outstanding segment to `c`'s retransmit ring.
 * Returns -1 without touching anything if the ring is already full
 * (TCP_MAX_INFLIGHT) -- callers that need to guarantee tracking (the data
 * path) check tcp_tx_idle() first and shouldn't normally hit this; tcp_close()
 * doesn't, so a FIN sent while the ring happens to be completely full is
 * still transmitted once by tcp_xmit_track() but not retransmitted, a rare
 * and non-corrupting degradation rather than overwriting another segment's
 * tracking the way the old single-slot design would have. */
static int rtx_push(struct conn *c, uint8_t flags, uint32_t seq,
                    const void *data, unsigned len)
{
    if (c->rtx_count >= TCP_MAX_INFLIGHT)
        return -1;
    if (len > TCP_TX_MAX) len = TCP_TX_MAX;
    int idx = (c->rtx_head + c->rtx_count) % TCP_MAX_INFLIGHT;
    struct rtx *r = &c->rtx[idx];
    if (data && len) memcpy(r->data, data, len);
    r->len     = len;
    r->flags   = flags;
    r->seq     = seq;
    r->used    = 1;
    r->last_ms = net_now_ms();
    r->rto_ms  = TCP_RTO_MS;
    r->retries = 0;
    c->rtx_count++;
    if ((unsigned)c->rtx_count > stats.max_inflight)
        stats.max_inflight = (unsigned)c->rtx_count;
    return 0;
}

/* Send a sequence-consuming segment and queue it for retransmission (see
 * rtx_push()). The segment is transmitted at most once here regardless of
 * whether it gets tracked -- tcp_tick() retries a *tracked* segment on RTO
 * (TCP_RTO_MS, doubling, up to TCP_MAX_RETX attempts each); that machinery
 * exists specifically to recover a transient send failure, the same as it
 * recovers ordinary packet loss on the wire, so a failed tcp_xmit() here
 * isn't itself surfaced as an error -- a send() succeeding has only ever
 * meant "queued for delivery," not "delivered." */
static int tcp_xmit_track(struct conn *c, uint8_t flags, uint32_t seq,
                          const void *data, unsigned len)
{
    if (len > TCP_TX_MAX) len = TCP_TX_MAX;

    int r = 0;
    if ((flags & TCP_PSH) && test_drop_data) {
        test_drop_data = 0;             /* test hook: pretend this one was lost */
    } else {
        r = tcp_xmit(c, flags, seq, c->tcb.rcv_nxt, data, len);
    }
    rtx_push(c, flags, seq, data, len);
    return r;
}

void tcp_test_drop_next_data(void) { test_drop_data = 1; }

/* Arm SYN retransmission (the SYN itself is sent by tcp_connect's ARP loop). */
static void rtx_save_syn(struct conn *c)
{
    rtx_push(c, TCP_SYN, c->tcb.iss, NULL, 0);
}

int tcp_send(int h, const void *data, size_t len)
{
    struct conn *c = conn_of(h);
    if (!c || c->tcb.state != TCP_ESTABLISHED || !data)
        return -1;
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;                        /* one segment only, no splitting */
    /* Phase 18.4.1: the caller (net/tcpsock.c's tsk_write()) is expected to
     * have already checked tcp_tx_idle() -- this is a defensive backstop,
     * not the primary gate, matching the old single-slot design's exact
     * contract (tcp_send() assumes the caller checked room first). */
    if (c->rtx_count >= TCP_MAX_INFLIGHT)
        return -1;
    uint32_t in_flight = c->tcb.snd_nxt - c->tcb.snd_una;   /* wrap-safe */
    if (in_flight + len > c->tcb.snd_wnd)
        return -1;                               /* peer's advertised window is full */
    /* Phase 17.5.2: queuing this segment into the retransmit ring happens
     * REGARDLESS of whether the immediate tcp_xmit() attempt inside
     * tcp_xmit_track() actually succeeded -- see its own comment. This used
     * to instead surface that first attempt's return value straight to the
     * caller as a hard failure, *without* advancing snd_nxt -- turning an
     * ordinary, already-queued, about-to-be-retried segment into an
     * immediate, unretried error one layer up, for no reason a real TCP
     * send() should ever fail outright. If the underlying problem is NOT
     * transient, repeated RTO failures still correctly close the connection
     * via TCP_MAX_RETX, just after a real retry attempt instead of on the
     * very first one. */
    tcp_xmit_track(c, TCP_PSH | TCP_ACK, c->tcb.snd_nxt, data, (unsigned)len);
    c->tcb.snd_nxt += (uint32_t)len;            /* data consumes sequence space */
    return (int)len;
}

int tcp_recv(int h, void *buf, size_t cap)
{
    struct conn *c = conn_of(h);
    if (!c)
        return 0;
    unsigned n = rxring_pop(&c->rx, (uint8_t *)buf, (unsigned)cap);
    if (n) {
        /* Draining frees ring space, so our receive window reopens. If we had
         * advertised a closed window (peer paused), send a window update now so
         * it resumes promptly instead of waiting on its persist timer. */
        unsigned was = c->tcb.rcv_wnd;
        c->tcb.rcv_wnd = (uint16_t)rxring_free(&c->rx);
        if (was == 0 && c->tcb.rcv_wnd > 0 &&
            (c->tcb.state == TCP_ESTABLISHED ||
             c->tcb.state == TCP_FIN_WAIT_1 || c->tcb.state == TCP_FIN_WAIT_2))
            tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);
    }
    return (int)n;
}

int tcp_rx_total(int h)
{
    struct conn *c = conn_of(h);
    return c ? (int)c->rx_total : 0;
}

/* Phase 18.3: bytes currently sitting in the RX ring, unread -- unlike
 * tcp_recv(), this doesn't consume anything, so it's safe for a mere
 * readiness check (tcpsock_poll()). */
int tcp_rx_avail(int h)
{
    struct conn *c = conn_of(h);
    return c ? (int)rxring_used(&c->rx) : 0;
}

wait_queue_t *tcp_conn_waitq(int h)
{
    struct conn *c = conn_of(h);
    return c ? &c->rwq : NULL;
}

/* Phase 18.4.1: "idle" now means "room for at least one more segment," not
 * "the single slot is empty" -- true as soon as EITHER the ring has a free
 * slot AND the peer's advertised window has room, which is what actually
 * lets net/tcpsock.c's tsk_write() pipeline several chunks of one write()
 * back to back instead of stopping to wait for each one's ACK. */
int tcp_tx_idle(int h)
{
    struct conn *c = conn_of(h);
    if (!c)
        return 1;
    if (c->rtx_count >= TCP_MAX_INFLIGHT)
        return 0;
    uint32_t in_flight = c->tcb.snd_nxt - c->tcb.snd_una;   /* wrap-safe */
    return in_flight < c->tcb.snd_wnd;
}

int tcp_close(int h)
{
    struct conn *c = conn_of(h);
    if (!c)
        return -1;
    if (c->tcb.state == TCP_ESTABLISHED) {              /* active close */
        tcp_xmit_track(c, TCP_FIN | TCP_ACK, c->tcb.snd_nxt, NULL, 0);
        c->tcb.snd_nxt += 1;                            /* FIN consumes a seq */
        c->tcb.state = TCP_FIN_WAIT_1;
        return 0;
    }
    if (c->tcb.state == TCP_CLOSE_WAIT) {               /* finish passive close */
        tcp_xmit_track(c, TCP_FIN | TCP_ACK, c->tcb.snd_nxt, NULL, 0);
        c->tcb.snd_nxt += 1;
        c->tcb.state = TCP_LAST_ACK;
        return 0;
    }
    return -1;
}

void tcp_tick(void)
{
    uint64_t now = net_now_ms();
    for (int i = 0; i < TCP_MAX_CONN; i++) {
        struct conn *c = &conns[i];
        if (!c->used)
            continue;

        /* A RST (tcp_input()'s TCP_RST handling) or any other path that tears
         * the connection down doesn't itself clear the ring -- without this
         * check, every segment still queued before the teardown kept being
         * blindly retransmitted on a connection that's already CLOSED (or
         * otherwise no longer live), spamming a peer that has long since
         * forgotten this connection existed. */
        if (c->rtx_count > 0 && c->tcb.state == TCP_CLOSED) {
            c->rtx_count = 0;
            c->rtx_head = 0;
            continue;
        }

        /* Phase 18.4.1: walk every outstanding segment (oldest first),
         * retransmitting whichever ones' own RTO elapsed independently --
         * with several in flight, an ACK for an earlier one doesn't mean a
         * later one arrived too. */
        for (int k = 0; k < c->rtx_count; k++) {
            int idx = (c->rtx_head + k) % TCP_MAX_INFLIGHT;
            struct rtx *r = &c->rtx[idx];
            if (now - r->last_ms < r->rto_ms)
                continue;
            if (r->retries >= TCP_MAX_RETX) {       /* give up entirely */
                c->rtx_count = 0;
                c->rtx_head = 0;
                c->tcb.state = TCP_CLOSED;
                break;
            }
            tcp_xmit(c, r->flags, r->seq, c->tcb.rcv_nxt, r->data, r->len);
            r->last_ms = now;
            r->retries++;
            r->rto_ms = r->rto_ms < TCP_RTO_MAX / 2
                      ? r->rto_ms * 2 : TCP_RTO_MAX;   /* backoff */
            stats.retransmits++;
        }

        if (c->tcb.state == TCP_TIME_WAIT && now >= c->tw_deadline)
            c->tcb.state = TCP_CLOSED;
    }
}

/* Allocate a slot: prefer a never-used one, else reuse a CLOSED one. */
static struct conn *alloc_conn(int *out_h)
{
    int closed = -1;
    for (int i = 0; i < TCP_MAX_CONN; i++) {
        if (!conns[i].used) { *out_h = i; return &conns[i]; }
        if (closed < 0 && conns[i].tcb.state == TCP_CLOSED) closed = i;
    }
    if (closed >= 0) { *out_h = closed; return &conns[closed]; }
    return NULL;
}

int tcp_connect(uint32_t dst, uint16_t port)
{
    int h = -1;
    struct conn *c = alloc_conn(&h);
    if (!c)
        return -1;                              /* table full */

    memset(c, 0, sizeof(*c));
    c->used = 1;
    rxring_init(&c->rx);
    c->tcb.local_ip    = IP_LOCAL;
    c->tcb.remote_ip   = dst;
    c->tcb.remote_port = port;
    c->tcb.local_port  = (uint16_t)(49152 + (perf_now_us() & 0x1fff));
    c->tcb.iss         = (uint32_t)perf_now_us();
    c->tcb.snd_una     = c->tcb.iss;
    c->tcb.snd_nxt     = c->tcb.iss + 1;        /* SYN consumes one sequence */
    c->tcb.rcv_wnd     = RX_RING_CAP;           /* free space in the receive ring */
    c->tcb.state       = TCP_SYN_SENT;
    stats.connects++;

    /* Transmit the SYN; retry only while the next-hop ARP is still resolving
     * (this is not TCP retransmission — just getting the first SYN onto the
     * wire once a MAC is known). */
    int sent = -1;
    uint64_t dl = net_now_ms() + 1500;
    while (net_now_ms() < dl) {
        sent = tcp_xmit(c, TCP_SYN, c->tcb.iss, 0, NULL, 0);
        if (sent == 0)
            break;
        net_poll();
    }
    if (sent != 0) {
        c->tcb.state = TCP_CLOSED;
        return -1;
    }
    rtx_save_syn(c);                            /* arm SYN retransmission */
    return h;
}

/* Demux to the connection matching the segment's 4-tuple (skipping CLOSED). */
static struct conn *find_conn(uint32_t src, uint16_t sport, uint16_t dport)
{
    for (int i = 0; i < TCP_MAX_CONN; i++) {
        struct conn *c = &conns[i];
        if (c->used && c->tcb.state != TCP_CLOSED &&
            c->tcb.remote_ip == src && c->tcb.remote_port == sport &&
            c->tcb.local_port == dport)
            return c;
    }
    return NULL;
}

void tcp_input(uint32_t src, const void *segment, size_t len)
{
    if (len < sizeof(struct tcp_hdr)) {
        stats.drops++;
        return;
    }
    if (tcp_checksum(src, IP_LOCAL, (const uint8_t *)segment, (unsigned)len) != 0) {
        stats.drops++;                          /* bad checksum: drop */
        return;
    }

    const struct tcp_hdr *h = (const struct tcp_hdr *)segment;
    struct conn *c = find_conn(src, ntohs(h->src_port), ntohs(h->dst_port));
    if (!c) {
        stats.drops++;                          /* no matching connection */
        return;
    }

    uint8_t  flags = h->flags;
    uint32_t seq   = ntohl(h->seq);
    uint32_t ack   = ntohl(h->ack);

    if (flags & TCP_RST) {                       /* peer refused / reset */
        stats.resets++;
        c->tcb.state = TCP_CLOSED;
        wait_wake_all(&c->rwq);      /* a blocked tsk_read() should notice promptly */
        return;
    }

    if (c->tcb.state == TCP_SYN_SENT) {
        /* Expect SYN+ACK acknowledging our SYN (ack == iss + 1). */
        if ((flags & TCP_SYN) && (flags & TCP_ACK) && ack == c->tcb.snd_nxt) {
            c->tcb.irs     = seq;
            c->tcb.rcv_nxt = seq + 1;            /* their SYN consumes one */
            c->tcb.snd_una = ack;
            c->tcb.snd_wnd = ntohs(h->window);
            c->tcb.state   = TCP_ESTABLISHED;
            c->rtx_count   = 0;                  /* our SYN is acknowledged */
            c->rtx_head    = 0;
            stats.established++;
            tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);  /* finish */
        }
        return;
    }

    /* ESTABLISHED and every closing state: track ACKs, accept in-order data,
     * consume an in-order FIN, then advance the state machine. */
    if (flags & TCP_ACK) {
        /* The window field is valid on every ACK, not just the SYN-ACK's --
         * Phase 18.4.1: this used to only ever be read once, at the
         * handshake, so tcp_send()/tcp_tx_idle() had no way to notice the
         * peer's real receive window shrinking or (from an initial zero)
         * opening up again. */
        c->tcb.snd_wnd = ntohs(h->window);
        if ((int32_t)(ack - c->tcb.snd_una) > 0) {
            c->tcb.snd_una = ack;                /* wrap-safe */
            /* Clear every fully-acked segment from the front of the ring --
             * ACKs are cumulative, so one ACK can free several at once
             * (e.g. catching up after a burst of several in-flight sends). */
            while (c->rtx_count > 0) {
                struct rtx *r = &c->rtx[c->rtx_head];
                uint32_t end = r->seq + seg_len(r->flags, r->len);
                if ((int32_t)(c->tcb.snd_una - end) < 0)
                    break;        /* oldest outstanding segment isn't fully acked yet */
                r->used = 0;
                c->rtx_head = (c->rtx_head + 1) % TCP_MAX_INFLIGHT;
                c->rtx_count--;
            }
        }
    }

    unsigned hlen = (unsigned)((h->data_off >> 4) & 0x0f) * 4;
    if (hlen < sizeof(struct tcp_hdr) || hlen > len)
        hlen = sizeof(struct tcp_hdr);
    const uint8_t *payload = (const uint8_t *)segment + hlen;
    unsigned plen = (unsigned)len - hlen;

    int receiving = (c->tcb.state == TCP_ESTABLISHED ||
                     c->tcb.state == TCP_FIN_WAIT_1 ||
                     c->tcb.state == TCP_FIN_WAIT_2);

    uint32_t before = c->tcb.rcv_nxt;
    if (plen > 0 && receiving) {
        if (seq == c->tcb.rcv_nxt) {
            /* All-or-nothing: accept the segment only if it fits whole. One
             * that doesn't fit is dropped *without* advancing rcv_nxt, so the
             * peer retransmits once our window reopens -- never silently
             * ACKed and lost (the old code advanced rcv_nxt by the full
             * length even when it had truncated the copy). */
            if (rxring_free(&c->rx) >= plen) {
                rxring_push(&c->rx, payload, plen);
                c->rx_total += plen;
                c->tcb.rcv_nxt += plen;

                /* Phase 18.4.2: this segment may have closed the gap before
                 * one or more segments we already held out of order --
                 * splice them in too, cascading as each one closes the next
                 * gap in turn. */
                int spliced;
                do {
                    spliced = 0;
                    for (int i = 0; i < TCP_MAX_OOO; i++) {
                        struct ooo_seg *o = &c->ooo[i];
                        if (!o->used || o->seq != c->tcb.rcv_nxt)
                            continue;
                        if (rxring_free(&c->rx) < o->len)
                            break;         /* ring full; leave it queued for later */
                        rxring_push(&c->rx, o->data, o->len);
                        c->rx_total += o->len;
                        c->tcb.rcv_nxt += o->len;
                        o->used = 0;
                        spliced = 1;
                    }
                } while (spliced);
            }
        } else if ((int32_t)(seq - c->tcb.rcv_nxt) > 0 && plen <= TCP_OOO_SEG_MAX) {
            /* Genuinely ahead of what we've got contiguously (a gap exists
             * before it) -- hold it instead of dropping it outright, so the
             * peer doesn't have to blindly resend data we may already have
             * buffered once the gap closes. */
            int found = -1, free_slot = -1;
            for (int i = 0; i < TCP_MAX_OOO; i++) {
                if (c->ooo[i].used && c->ooo[i].seq == seq) { found = i; break; }
                if (!c->ooo[i].used && free_slot < 0) free_slot = i;
            }
            if (found < 0 && free_slot >= 0) {
                struct ooo_seg *o = &c->ooo[free_slot];
                memcpy(o->data, payload, plen);
                o->len  = plen;
                o->seq  = seq;
                o->used = 1;
                stats.ooo_segments++;
            }
            /* else: a duplicate of one we already hold, or the holding area
             * is full -- either way, drop it silently. The ACK below still
             * tells the peer our real rcv_nxt, so its own retransmit timer
             * recovers it, same as it always has for a segment we can't
             * accept right now. */
        }
        /* (seq behind rcv_nxt: an old duplicate, already fully accounted
         * for -- nothing to store, just ACK it below as always.) */
        c->tcb.rcv_wnd = (uint16_t)rxring_free(&c->rx);   /* advertise true window */
    }

    int fin = 0;
    if ((flags & TCP_FIN) && (seq + plen) == c->tcb.rcv_nxt) {  /* in-order FIN */
        c->tcb.rcv_nxt += 1;                     /* FIN consumes a seq */
        fin = 1;
        stats.fins++;
    }
    /* Phase 17.5.2: RFC 793/5681 require an immediate ACK for a segment that
     * carries data or a FIN even when it does NOT advance rcv_nxt -- a
     * duplicate (already-received data retransmitted because our earlier ack
     * for it was never sent), a genuinely out-of-order segment, or one that
     * arrived in order but didn't fit the current window (the `rxring_free`
     * check above). Before this fix the condition below was only
     * `c->tcb.rcv_nxt != before`, so all three of those cases got ZERO
     * acknowledgment -- a real sender has no way to learn "you already have
     * this" or "here is my real window" short of its own retransmit timer.
     * Large-response stress testing reproduced this directly: a real TCP
     * sender (Linux, not a hand-rolled test peer) retransmitted an
     * already-received segment several times in a row with Aurora
     * completely silent in response, stalling the whole connection --
     * `tsk_read()`'s idle-read timeout then fired and got misread as a
     * clean peer close, silently truncating the response. Sending a current
     * ACK for every data/FIN-bearing segment, not just ones that advance
     * rcv_nxt, is what actually breaks that stall. */
    if (c->tcb.rcv_nxt != before || (plen > 0 && receiving) || (flags & TCP_FIN))
        tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);

    int our_fin_acked = (c->tcb.snd_una == c->tcb.snd_nxt);

    switch (c->tcb.state) {
    case TCP_ESTABLISHED:
        if (fin)
            c->tcb.state = TCP_CLOSE_WAIT;       /* peer closed first (passive) */
        break;
    case TCP_FIN_WAIT_1:
        if (our_fin_acked && fin) { c->tcb.state = TCP_TIME_WAIT; c->tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        else if (our_fin_acked)   c->tcb.state = TCP_FIN_WAIT_2;
        else if (fin)             c->tcb.state = TCP_CLOSING;
        break;
    case TCP_FIN_WAIT_2:
        if (fin) { c->tcb.state = TCP_TIME_WAIT; c->tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        break;
    case TCP_CLOSING:
        if (our_fin_acked) { c->tcb.state = TCP_TIME_WAIT; c->tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        break;
    case TCP_LAST_ACK:
        if (our_fin_acked) c->tcb.state = TCP_CLOSED;
        break;
    case TCP_TIME_WAIT:
        if (flags & TCP_FIN)                     /* re-ack a retransmitted FIN */
            tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);
        break;
    default:
        break;
    }

    /* Phase 18.1.5: wake a reader blocked in tsk_read()'s wait_event_timeout()
     * as soon as this segment brought new data, a FIN, or any state change --
     * covers the case where a DIFFERENT thread's net_poll() (not the blocked
     * reader's own) is what actually delivered this segment. Not required for
     * correctness (the reader's own short timeout re-polls regardless), just
     * saves it up to that timeout's worth of latency. */
    wait_wake_all(&c->rwq);
}
