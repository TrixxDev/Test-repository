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

#define TCP_RCV_WND  8192

static struct tcp_tcb tcb;          /* the single Phase-1 connection */

void tcp_init(void)
{
    memset(&tcb, 0, sizeof(tcb));
    tcb.state = TCP_CLOSED;
}

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

/* Send a header-only segment (no payload — all Phase 1 needs). */
static int tcp_xmit(uint8_t flags, uint32_t seq, uint32_t ack)
{
    uint8_t buf[sizeof(struct tcp_hdr)];
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
    h->checksum = htons(tcp_checksum(tcb.local_ip, tcb.remote_ip,
                                     buf, sizeof(buf)));
    return ipv4_send(tcb.remote_ip, IPPROTO_TCP, buf, sizeof(buf));
}

int tcp_connect(uint32_t dst, uint16_t port)
{
    memset(&tcb, 0, sizeof(tcb));
    tcb.local_ip    = IP_LOCAL;
    tcb.remote_ip   = dst;
    tcb.remote_port = port;
    tcb.local_port  = (uint16_t)(49152 + (perf_now_us() & 0x1fff));
    tcb.iss         = (uint32_t)perf_now_us();
    tcb.snd_una     = tcb.iss;
    tcb.snd_nxt     = tcb.iss + 1;              /* SYN consumes one sequence */
    tcb.rcv_wnd     = TCP_RCV_WND;
    tcb.state       = TCP_SYN_SENT;

    /* Transmit the SYN; retry only while the next-hop ARP is still resolving
     * (this is not TCP retransmission — just getting the first SYN onto the
     * wire once a MAC is known). */
    int sent = -1;
    uint64_t dl = net_now_ms() + 1500;
    while (net_now_ms() < dl) {
        sent = tcp_xmit(TCP_SYN, tcb.iss, 0);
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
    if (len < sizeof(struct tcp_hdr) || tcb.state == TCP_CLOSED)
        return;
    if (tcp_checksum(src, tcb.local_ip, (const uint8_t *)segment, (unsigned)len) != 0)
        return;                                 /* bad checksum: drop */

    const struct tcp_hdr *h = (const struct tcp_hdr *)segment;

    /* Single-connection demux: must match our 4-tuple. */
    if (src != tcb.remote_ip ||
        ntohs(h->src_port) != tcb.remote_port ||
        ntohs(h->dst_port) != tcb.local_port)
        return;

    uint8_t  flags = h->flags;
    uint32_t seq   = ntohl(h->seq);
    uint32_t ack   = ntohl(h->ack);

    if (flags & TCP_RST) {                       /* peer refused / reset */
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
            tcp_xmit(TCP_ACK, tcb.snd_nxt, tcb.rcv_nxt);   /* complete the handshake */
        }
        return;
    }

    /* ESTABLISHED and beyond: data transfer / teardown are Phase 2/3. */
}
