/* TCP client connections over a fixed connection table — see tcp.h. */
#include "tcp.h"
#include "rxring.h"
#include "ipv4.h"
#include "netstack.h"
#include "inet.h"
#include "perf.h"
#include "string.h"

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

/* Minimal retransmission: cache the one outstanding sequence-consuming segment
 * (SYN / data / FIN); a pure ACK is never retransmitted. On RTO with no ACK, the
 * segment is resent (with a refreshed ack/window); on ACK past its end, cleared. */
struct rtx {
    uint8_t   data[TCP_TX_MAX];
    unsigned  len;              /* payload bytes */
    uint8_t   flags;
    uint32_t  seq;
    int       pending;
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
    struct rtx rtx;
    int       used;
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

/* Send a sequence-consuming segment and cache it for retransmission.
 *
 * `c->rtx` holds exactly ONE outstanding segment -- calling this again
 * while a previous one is still `pending` (unacknowledged) overwrites it,
 * losing that earlier segment's own retry tracking. In practice
 * net/tcpsock.c's tsk_write() already waits for `tcp_tx_idle()` (this slot
 * going non-pending) after every chunk it sends, including a single-chunk
 * write, before returning -- so two back-to-back tcp_send() calls from
 * different write() calls (e.g. user/httpsget.c's h2_maybe_send_window_update()
 * sending the stream-level then connection-level WINDOW_UPDATE) only
 * collide if the first segment's ACK genuinely doesn't arrive within that
 * 4-second wait, a real loss on top of an already-slow path. Not fixed
 * here -- doing so properly means tracking more than one in-flight segment,
 * a bigger change than this phase's own confirmed bug (see tcp_send()'s
 * comment) needs. */
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

    if (data && len) memcpy(c->rtx.data, data, len);
    c->rtx.len     = len;
    c->rtx.flags   = flags;
    c->rtx.seq     = seq;
    c->rtx.pending = 1;
    c->rtx.last_ms = net_now_ms();
    c->rtx.rto_ms  = TCP_RTO_MS;
    c->rtx.retries = 0;
    return r;
}

void tcp_test_drop_next_data(void) { test_drop_data = 1; }

/* Arm SYN retransmission (the SYN itself is sent by tcp_connect's ARP loop). */
static void rtx_save_syn(struct conn *c)
{
    c->rtx.len = 0;
    c->rtx.flags   = TCP_SYN;
    c->rtx.seq     = c->tcb.iss;
    c->rtx.pending = 1;
    c->rtx.last_ms = net_now_ms();
    c->rtx.rto_ms  = TCP_RTO_MS;
    c->rtx.retries = 0;
}

int tcp_send(int h, const void *data, size_t len)
{
    struct conn *c = conn_of(h);
    if (!c || c->tcb.state != TCP_ESTABLISHED || !data)
        return -1;
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;                        /* one segment only, no splitting */
    /* Phase 17.5.2: tcp_xmit_track() below queues this segment into c->rtx
     * -- pending, with its own seq/data/RTO -- REGARDLESS of whether the
     * immediate tcp_xmit() attempt inside it actually succeeded. tcp_tick()
     * already retries a pending segment on RTO (TCP_RTO_MS, doubling, up to
     * TCP_MAX_RETX attempts) -- that machinery exists specifically to
     * recover a transient send failure, the same as it recovers ordinary
     * packet loss on the wire. This used to instead surface that first
     * attempt's return value straight to the caller as a hard failure,
     * *without* advancing snd_nxt -- turning an ordinary, already-queued,
     * about-to-be-retried segment into an immediate, unretried error one
     * layer up, for no reason a real TCP send() should ever fail outright:
     * a send() succeeding has only ever meant "queued for delivery," not
     * "delivered." If the underlying problem is NOT transient, repeated
     * RTO failures still correctly close the connection via TCP_MAX_RETX,
     * just after a real retry attempt instead of on the very first one. */
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

int tcp_tx_idle(int h)
{
    struct conn *c = conn_of(h);
    return !c || !c->rtx.pending;
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

        /* A RST (tcp_input()'s TCP_RST handling) or any other path that
         * tears the connection down doesn't itself clear rtx.pending --
         * without this check, a segment queued before the teardown kept
         * being blindly retransmitted on a connection that's already
         * CLOSED (or otherwise no longer live), spamming a peer that has
         * long since forgotten this connection existed. */
        if (c->rtx.pending && c->tcb.state == TCP_CLOSED) {
            c->rtx.pending = 0;
            continue;
        }

        /* Retransmit the outstanding segment if its RTO elapsed. */
        if (c->rtx.pending && now - c->rtx.last_ms >= c->rtx.rto_ms) {
            if (c->rtx.retries >= TCP_MAX_RETX) {       /* give up */
                c->rtx.pending = 0;
                c->tcb.state = TCP_CLOSED;
            } else {
                tcp_xmit(c, c->rtx.flags, c->rtx.seq, c->tcb.rcv_nxt,
                         c->rtx.data, c->rtx.len);
                c->rtx.last_ms = now;
                c->rtx.retries++;
                c->rtx.rto_ms = c->rtx.rto_ms < TCP_RTO_MAX / 2
                              ? c->rtx.rto_ms * 2 : TCP_RTO_MAX;   /* backoff */
                stats.retransmits++;
            }
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
            c->rtx.pending = 0;                  /* our SYN is acknowledged */
            stats.established++;
            tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);  /* finish */
        }
        return;
    }

    /* ESTABLISHED and every closing state: track ACKs, accept in-order data,
     * consume an in-order FIN, then advance the state machine. */
    if ((flags & TCP_ACK) && (int32_t)(ack - c->tcb.snd_una) > 0) {
        c->tcb.snd_una = ack;                    /* wrap-safe */
        /* Clear the retransmit cache once its segment is fully acknowledged. */
        if (c->rtx.pending) {
            uint32_t end = c->rtx.seq + seg_len(c->rtx.flags, c->rtx.len);
            if ((int32_t)(c->tcb.snd_una - end) >= 0)
                c->rtx.pending = 0;
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
    if (plen > 0 && seq == c->tcb.rcv_nxt && receiving) {   /* in-order data only */
        /* All-or-nothing: accept the segment only if it fits whole. One that
         * doesn't fit is dropped *without* advancing rcv_nxt, so the peer
         * retransmits once our window reopens -- never silently ACKed and lost
         * (the old code advanced rcv_nxt by the full length even when it had
         * truncated the copy). */
        if (rxring_free(&c->rx) >= plen) {
            rxring_push(&c->rx, payload, plen);
            c->rx_total += plen;
            c->tcb.rcv_nxt += plen;
        }
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
}
