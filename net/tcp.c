/* TCP client handshake (Phase 1) — see tcp.h. */
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
#define TCP_RX_CAP    8192          /* receive buffer (one in-order stream) */
#define TCP_TX_MAX    1400          /* one segment, well under the MTU */
#define TCP_TIME_WAIT_MS 1000       /* shortened 2*MSL (real TCP: minutes) */

static struct tcp_tcb tcb;          /* the single connection */
static uint8_t  rx_buf[TCP_RX_CAP];
static unsigned rx_len;             /* bytes accumulated */
static unsigned rx_read;            /* bytes handed to tcp_recv */
static uint64_t tw_deadline;        /* TIME_WAIT -> CLOSED moment */
static struct tcp_stats stats;      /* lifetime counters */

void tcp_init(void)
{
    memset(&tcb, 0, sizeof(tcb));
    tcb.state = TCP_CLOSED;
    rx_len = rx_read = 0;
    memset(&stats, 0, sizeof(stats));
}

void tcp_get_stats(struct tcp_stats *out) { if (out) *out = stats; }

int tcp_state(void) { return tcb.state; }

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

/* Send a segment with `flags`, optionally carrying `len` payload bytes. */
static int tcp_xmit(uint8_t flags, uint32_t seq, uint32_t ack,
                    const void *data, unsigned len)
{
    static uint8_t buf[sizeof(struct tcp_hdr) + TCP_TX_MAX];
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;

    struct tcp_hdr *h = (struct tcp_hdr *)buf;
    h->src_port = htons(tcb.local_port);
    h->dst_port = htons(tcb.remote_port);
    h->seq      = htonl(seq);
    h->ack      = htonl(ack);
    h->data_off = 5 << 4;                       /* 20-byte header, no options */
    h->flags    = flags;
    h->window   = htons(tcb.rcv_wnd);
    h->checksum = 0;
    h->urg_ptr  = 0;
    if (len)
        memcpy(buf + sizeof(struct tcp_hdr), data, len);

    unsigned total = sizeof(struct tcp_hdr) + len;
    h->checksum = htons(tcp_checksum(tcb.local_ip, tcb.remote_ip, buf, total));
    return ipv4_send(tcb.remote_ip, IPPROTO_TCP, buf, total);
}

int tcp_send(const void *data, size_t len)
{
    if (tcb.state != TCP_ESTABLISHED || !data)
        return -1;
    if (len > TCP_TX_MAX)
        len = TCP_TX_MAX;                        /* one segment only, no splitting */
    if (tcp_xmit(TCP_PSH | TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, data, (unsigned)len) != 0)
        return -1;
    tcb.snd_nxt += (uint32_t)len;               /* data consumes sequence space */
    return (int)len;
}

int tcp_recv(void *buf, size_t cap)
{
    unsigned avail = rx_len - rx_read;
    unsigned n = avail < cap ? avail : (unsigned)cap;
    if (n)
        memcpy(buf, rx_buf + rx_read, n);
    rx_read += n;
    return (int)n;
}

int tcp_rx_total(void) { return (int)rx_len; }

int tcp_close(void)
{
    if (tcb.state == TCP_ESTABLISHED) {                 /* active close */
        tcp_xmit(TCP_FIN | TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, NULL, 0);
        tcb.snd_nxt += 1;                               /* FIN consumes a seq */
        tcb.state = TCP_FIN_WAIT_1;
        return 0;
    }
    if (tcb.state == TCP_CLOSE_WAIT) {                  /* finish passive close */
        tcp_xmit(TCP_FIN | TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, NULL, 0);
        tcb.snd_nxt += 1;
        tcb.state = TCP_LAST_ACK;
        return 0;
    }
    return -1;
}

void tcp_tick(void)
{
    if (tcb.state == TCP_TIME_WAIT && net_now_ms() >= tw_deadline)
        tcb.state = TCP_CLOSED;
}

int tcp_connect(uint32_t dst, uint16_t port)
{
    memset(&tcb, 0, sizeof(tcb));
    rx_len = rx_read = 0;
    tcb.local_ip    = IP_LOCAL;
    tcb.remote_ip   = dst;
    tcb.remote_port = port;
    tcb.local_port  = (uint16_t)(49152 + (perf_now_us() & 0x1fff));
    tcb.iss         = (uint32_t)perf_now_us();
    tcb.snd_una     = tcb.iss;
    tcb.snd_nxt     = tcb.iss + 1;              /* SYN consumes one sequence */
    tcb.rcv_wnd     = TCP_RCV_WND;
    tcb.state       = TCP_SYN_SENT;
    stats.connects++;

    /* Transmit the SYN; retry only while the next-hop ARP is still resolving
     * (this is not TCP retransmission — just getting the first SYN onto the
     * wire once a MAC is known). */
    int sent = -1;
    uint64_t dl = net_now_ms() + 1500;
    while (net_now_ms() < dl) {
        sent = tcp_xmit(TCP_SYN, tcb.iss, 0, NULL, 0);
        if (sent == 0)
            break;
        net_poll();
    }
    if (sent != 0) {
        tcb.state = TCP_CLOSED;
        return -1;
    }
    return 0;
}

void tcp_input(uint32_t src, const void *segment, size_t len)
{
    if (tcb.state == TCP_CLOSED)
        return;
    if (len < sizeof(struct tcp_hdr)) {
        stats.drops++;
        return;
    }
    if (tcp_checksum(src, tcb.local_ip, (const uint8_t *)segment, (unsigned)len) != 0) {
        stats.drops++;                          /* bad checksum: drop */
        return;
    }

    const struct tcp_hdr *h = (const struct tcp_hdr *)segment;

    /* Single-connection demux: must match our 4-tuple. */
    if (src != tcb.remote_ip ||
        ntohs(h->src_port) != tcb.remote_port ||
        ntohs(h->dst_port) != tcb.local_port) {
        stats.drops++;
        return;
    }

    uint8_t  flags = h->flags;
    uint32_t seq   = ntohl(h->seq);
    uint32_t ack   = ntohl(h->ack);

    if (flags & TCP_RST) {                       /* peer refused / reset */
        stats.resets++;
        tcb.state = TCP_CLOSED;
        return;
    }

    if (tcb.state == TCP_SYN_SENT) {
        /* Expect SYN+ACK acknowledging our SYN (ack == iss + 1). */
        if ((flags & TCP_SYN) && (flags & TCP_ACK) && ack == tcb.snd_nxt) {
            tcb.irs     = seq;
            tcb.rcv_nxt = seq + 1;               /* their SYN consumes one */
            tcb.snd_una = ack;
            tcb.snd_wnd = ntohs(h->window);
            tcb.state   = TCP_ESTABLISHED;
            stats.established++;
            tcp_xmit(TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, NULL, 0);  /* finish handshake */
        }
        return;
    }

    if (tcb.state == TCP_CLOSED || tcb.state == TCP_SYN_RECEIVED)
        return;

    /* ESTABLISHED and every closing state: track ACKs, accept in-order data,
     * consume an in-order FIN, then advance the state machine. */
    if ((flags & TCP_ACK) && (int32_t)(ack - tcb.snd_una) > 0)
        tcb.snd_una = ack;                       /* wrap-safe */

    unsigned hlen = (unsigned)((h->data_off >> 4) & 0x0f) * 4;
    if (hlen < sizeof(struct tcp_hdr) || hlen > len)
        hlen = sizeof(struct tcp_hdr);
    const uint8_t *payload = (const uint8_t *)segment + hlen;
    unsigned plen = (unsigned)len - hlen;

    int receiving = (tcb.state == TCP_ESTABLISHED ||
                     tcb.state == TCP_FIN_WAIT_1 ||
                     tcb.state == TCP_FIN_WAIT_2);

    uint32_t before = tcb.rcv_nxt;
    if (plen > 0 && seq == tcb.rcv_nxt && receiving) {   /* in-order data only */
        unsigned space = (rx_len < TCP_RX_CAP) ? TCP_RX_CAP - rx_len : 0;
        unsigned n = plen < space ? plen : space;
        if (n)
            memcpy(rx_buf + rx_len, payload, n);
        rx_len += n;
        tcb.rcv_nxt += plen;
    }

    int fin = 0;
    if ((flags & TCP_FIN) && (seq + plen) == tcb.rcv_nxt) {  /* in-order FIN */
        tcb.rcv_nxt += 1;                        /* FIN consumes a seq */
        fin = 1;
        stats.fins++;
    }
    if (tcb.rcv_nxt != before)
        tcp_xmit(TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, NULL, 0);

    int our_fin_acked = (tcb.snd_una == tcb.snd_nxt);

    switch (tcb.state) {
    case TCP_ESTABLISHED:
        if (fin)
            tcb.state = TCP_CLOSE_WAIT;          /* peer closed first (passive) */
        break;
    case TCP_FIN_WAIT_1:
        if (our_fin_acked && fin) { tcb.state = TCP_TIME_WAIT; tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        else if (our_fin_acked)   tcb.state = TCP_FIN_WAIT_2;
        else if (fin)             tcb.state = TCP_CLOSING;
        break;
    case TCP_FIN_WAIT_2:
        if (fin) { tcb.state = TCP_TIME_WAIT; tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        break;
    case TCP_CLOSING:
        if (our_fin_acked) { tcb.state = TCP_TIME_WAIT; tw_deadline = net_now_ms() + TCP_TIME_WAIT_MS; }
        break;
    case TCP_LAST_ACK:
        if (our_fin_acked) tcb.state = TCP_CLOSED;
        break;
    case TCP_TIME_WAIT:
        if (flags & TCP_FIN)                     /* re-ack a retransmitted FIN */
            tcp_xmit(TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt, NULL, 0);
        break;
    default:
        break;
    }
}
