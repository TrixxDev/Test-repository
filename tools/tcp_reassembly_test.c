/* Phase 18.4.2 acceptance: TCP out-of-order receive reassembly, tested on
 * the host by calling net/tcp.c's real tcp_input()/tcp_recv() directly with
 * hand-crafted segments fed in a deliberately scrambled order -- QEMU's
 * SLIRP network can't be told to reorder packets on the wire, but this can
 * exercise the exact same code with full, deterministic control.
 *
 * Everything net/tcp.c reaches outside itself (the real network device, the
 * scheduler's wait queues, the PIT/TSC clocks) is stubbed below: this test
 * cares about tcp_input()'s reassembly logic, not sending real packets or
 * blocking real threads.
 *
 * This independently reimplements the TCP segment wire format (struct
 * tcp_hdr and its checksum are private to net/tcp.c) rather than reusing
 * Aurora's own encoder, the same "prove the real wire format, don't just
 * link against the same code" discipline the tools/h2_*.py test peers use
 * for HTTP/2. */
#include "tcp.h"
#include "scheduler.h"
#include "netcfg.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---- stubs: everything net/tcp.c calls outside itself ---- */
struct net_config g_net_config = { 0x0a000001u, 0xffffff00u, 0x0a000002u, { 0, 0 } };

static uint64_t fake_ms;
uint64_t net_now_ms(void) { return fake_ms; }

static uint64_t fake_us;
uint64_t perf_now_us(void) { return fake_us++; }   /* deterministic, increasing */

int ipv4_send(uint32_t dst, uint8_t proto, const void *payload, size_t len)
{
    (void)dst; (void)proto; (void)payload; (void)len;
    return 0;    /* pretend every send goes out fine; this test never inspects it */
}

void wait_wake_all(wait_queue_t *wq) { (void)wq; }
void net_poll(void) { }   /* never reached: our ipv4_send() stub always "succeeds" */

/* ---- independent TCP segment encoder (mirrors net/tcp.c's private struct tcp_hdr) ---- */
struct tcp_hdr {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  data_off, flags;
    uint16_t window, checksum, urg_ptr;
} __attribute__((packed));

#define F_SYN 0x02
#define F_ACK 0x10

static uint16_t htons_(uint16_t x) { return (uint16_t)((x << 8) | (x >> 8)); }
static uint32_t htonl_(uint32_t x)
{
    return ((x & 0xffu) << 24) | ((x & 0xff00u) << 8) | ((x & 0xff0000u) >> 8) | ((x & 0xff000000u) >> 24);
}

static uint16_t tcp_csum(uint32_t src, uint32_t dst, const uint8_t *seg, unsigned len)
{
    uint32_t sum = 0;
    sum += (src >> 16) & 0xffff; sum += src & 0xffff;
    sum += (dst >> 16) & 0xffff; sum += dst & 0xffff;
    sum += 6 /* IPPROTO_TCP */;
    sum += len;
    for (unsigned i = 0; i + 1 < len; i += 2) sum += ((uint32_t)seg[i] << 8) | seg[i + 1];
    if (len & 1) sum += (uint32_t)seg[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Builds one segment into `out`, returns its total length. */
static unsigned build_seg(uint8_t *out, uint32_t local_ip, uint32_t peer_ip,
                          uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                          uint8_t flags, uint16_t window, const void *payload, unsigned plen)
{
    struct tcp_hdr *h = (struct tcp_hdr *)out;
    h->src_port = htons_(sport);
    h->dst_port = htons_(dport);
    h->seq = htonl_(seq);
    h->ack = htonl_(ack);
    h->data_off = 5 << 4;
    h->flags = flags;
    h->window = htons_(window);
    h->checksum = 0;
    h->urg_ptr = 0;
    if (plen) memcpy(out + sizeof(*h), payload, plen);
    unsigned total = (unsigned)sizeof(*h) + plen;
    h->checksum = htons_(tcp_csum(peer_ip, local_ip, out, total));   /* segment is FROM peer TO us */
    return total;
}

static int fails;
static void check(const char *name, int ok)
{
    printf("%-85s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

int main(void)
{
    tcp_init();

    uint32_t peer_ip = 0x0a000002u;    /* 10.0.0.2, arbitrary */
    uint16_t peer_port = 9000;

    int h = tcp_connect(peer_ip, peer_port);
    check("tcp_connect() returns a valid handle", h >= 0);
    check("state is SYN_SENT right after connect", tcp_state(h) == TCP_SYN_SENT);

    /* We know the exact iss/local_port tcp_connect() picked: our perf_now_us()
     * stub is a deterministic, ever-increasing counter, called local_port
     * first (fake_us=0) then iss (fake_us=1). */
    uint16_t local_port = (uint16_t)(49152 + (0 & 0x1fff));
    uint32_t our_iss = 1;
    uint32_t peer_iss = 5000;

    uint8_t seg[128];
    unsigned n;

    /* --- complete the handshake with a synthetic SYN-ACK --- */
    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss, our_iss + 1, F_SYN | F_ACK, 65535, NULL, 0);
    tcp_input(peer_ip, seg, n);
    check("SYN-ACK moves the connection to ESTABLISHED", tcp_state(h) == TCP_ESTABLISHED);

    /* --- three chunks of one message, fed to tcp_input() in scrambled order --- */
    const char *part_a = "HELLO_";       /* seq peer_iss+1  .. +6  */
    const char *part_b = "WORLD_";       /* seq peer_iss+7  .. +12 */
    const char *part_c = "TEST_DATA_XYZ"; /* seq peer_iss+13 .. +25 */
    unsigned la = 6, lb = 6, lc = 13;

    struct tcp_stats s0, s1;
    tcp_get_stats(&s0);

    /* Feed C first (seq far ahead -- a gap of 12 bytes before it), then B
     * (also ahead -- a gap of 6 bytes before it), then A (exactly in order,
     * which should trigger the cascade splicing B then C in behind it). */
    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss + 1 + la + lb, our_iss + 1, F_ACK, 65535, part_c, lc);
    tcp_input(peer_ip, seg, n);

    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss + 1 + la, our_iss + 1, F_ACK, 65535, part_b, lb);
    tcp_input(peer_ip, seg, n);

    check("nothing delivered to the app yet (A, the missing piece, hasn't arrived)",
          tcp_rx_avail(h) == 0);

    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss + 1, our_iss + 1, F_ACK, 65535, part_a, la);
    tcp_input(peer_ip, seg, n);

    tcp_get_stats(&s1);
    check("both out-of-order segments (B and C) were counted as held",
          s1.ooo_segments - s0.ooo_segments == 2);

    check("all three parts are now available, in order, after the cascade",
          tcp_rx_avail(h) == (int)(la + lb + lc));

    char out[64] = {0};
    int got = tcp_recv(h, out, sizeof(out) - 1);
    char expected[64];
    snprintf(expected, sizeof(expected), "%s%s%s", part_a, part_b, part_c);
    check("tcp_recv() returns the exact byte count", got == (int)(la + lb + lc));
    check("reassembled bytes are correct and in the right order (not scrambled)",
          got > 0 && memcmp(out, expected, (unsigned)got) == 0);

    /* --- a duplicate of an already-held out-of-order segment is ignored, not double-counted --- */
    tcp_get_stats(&s0);
    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss + 1 + la + lb + lc + 100, our_iss + 1, F_ACK, 65535, "X", 1);
    tcp_input(peer_ip, seg, n);          /* one genuinely new out-of-order segment */
    tcp_input(peer_ip, seg, n);          /* the exact same segment again -- a real duplicate */
    tcp_get_stats(&s1);
    check("a duplicate out-of-order segment isn't counted twice",
          s1.ooo_segments - s0.ooo_segments == 1);

    printf("\n18.4.2 TCP OUT-OF-ORDER REASSEMBLY: %s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
    return fails ? 1 : 0;
}
