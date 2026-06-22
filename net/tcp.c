/* TCP client connections over a fixed connection table — see tcp.h. */
#include "tcp.h"
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

#define TCP_RCV_WND   8192
#define TCP_RX_CAP    8192          /* per-connection receive buffer */
#define TCP_TX_MAX    1400          /* one segment, well under the MTU */
#define TCP_TIME_WAIT_MS 1000       /* shortened 2*MSL (real TCP: minutes) */

/* One connection: its control block plus the buffering/timer state the public
 * TCB shape doesn't carry. `used` slots that reach CLOSED are reused by the next
 * connect (kept around first so a caller can drain trailing data after close). */
struct conn {
    struct tcp_tcb tcb;
    uint8_t   rx_buf[TCP_RX_CAP];
    unsigned  rx_len, rx_read;
    uint64_t  tw_deadline;      /* TIME_WAIT -> CLOSED moment */
    int       used;
};

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

int tcp_send(int h, const void *data, size_t len)
{
    struct conn *c = conn_of(h);
    if (!c || c->tcb.state != TCP_ESTABLISHED || !data)
        return -1;
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;                        /* one segment only, no splitting */
    if (tcp_xmit(c, TCP_PSH | TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, data, (unsigned)len) != 0)
        return -1;
    c->tcb.snd_nxt += (uint32_t)len;            /* data consumes sequence space */
    return (int)len;
}

int tcp_recv(int h, void *buf, size_t cap)
{
    struct conn *c = conn_of(h);
    if (!c)
        return 0;
    unsigned avail = c->rx_len - c->rx_read;
    unsigned n = avail < cap ? avail : (unsigned)cap;
    if (n)
        memcpy(buf, c->rx_buf + c->rx_read, n);
    c->rx_read += n;
    return (int)n;
}

int tcp_rx_total(int h)
{
    struct conn *c = conn_of(h);
    return c ? (int)c->rx_len : 0;
}

int tcp_close(int h)
{
    struct conn *c = conn_of(h);
    if (!c)
        return -1;
    if (c->tcb.state == TCP_ESTABLISHED) {              /* active close */
        tcp_xmit(c, TCP_FIN | TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);
        c->tcb.snd_nxt += 1;                            /* FIN consumes a seq */
        c->tcb.state = TCP_FIN_WAIT_1;
        return 0;
    }
    if (c->tcb.state == TCP_CLOSE_WAIT) {               /* finish passive close */
        tcp_xmit(c, TCP_FIN | TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);
        c->tcb.snd_nxt += 1;
        c->tcb.state = TCP_LAST_ACK;
        return 0;
    }
    return -1;
}

void tcp_tick(void)
{
    uint64_t now = net_now_ms();
    for (int i = 0; i < TCP_MAX_CONN; i++)
        if (conns[i].used && conns[i].tcb.state == TCP_TIME_WAIT &&
            now >= conns[i].tw_deadline)
            conns[i].tcb.state = TCP_CLOSED;
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
    c->tcb.local_ip    = IP_LOCAL;
    c->tcb.remote_ip   = dst;
    c->tcb.remote_port = port;
    c->tcb.local_port  = (uint16_t)(49152 + (perf_now_us() & 0x1fff));
    c->tcb.iss         = (uint32_t)perf_now_us();
    c->tcb.snd_una     = c->tcb.iss;
    c->tcb.snd_nxt     = c->tcb.iss + 1;        /* SYN consumes one sequence */
    c->tcb.rcv_wnd     = TCP_RCV_WND;
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
            stats.established++;
            tcp_xmit(c, TCP_ACK, c->tcb.snd_nxt, c->tcb.rcv_nxt, NULL, 0);  /* finish */
        }
        return;
    }

    /* ESTABLISHED and every closing state: track ACKs, accept in-order data,
     * consume an in-order FIN, then advance the state machine. */
    if ((flags & TCP_ACK) && (int32_t)(ack - c->tcb.snd_una) > 0)
        c->tcb.snd_una = ack;                    /* wrap-safe */

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
        unsigned space = (c->rx_len < TCP_RX_CAP) ? TCP_RX_CAP - c->rx_len : 0;
        unsigned n = plen < space ? plen : space;
        if (n)
            memcpy(c->rx_buf + c->rx_len, payload, n);
        c->rx_len += n;
        c->tcb.rcv_nxt += plen;
    }

    int fin = 0;
    if ((flags & TCP_FIN) && (seq + plen) == c->tcb.rcv_nxt) {  /* in-order FIN */
        c->tcb.rcv_nxt += 1;                     /* FIN consumes a seq */
        fin = 1;
        stats.fins++;
    }
    if (c->tcb.rcv_nxt != before)
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
