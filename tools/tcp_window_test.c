/* Phase 18.4.3 acceptance: TCP receive-window advertising and peer-window
 * respecting, tested on the host the same way tools/tcp_reassembly_test.c
 * tests 18.4.2 -- by calling net/tcp.c's real tcp_input()/tcp_recv()/
 * tcp_send() directly with hand-crafted segments, since driving the rx ring
 * to EXACTLY full (16384 bytes) and inspecting the window field of Aurora's
 * own outgoing segments needs precise, deterministic control QEMU's SLIRP
 * networking can't give us.
 *
 * Two scenarios:
 *  1. Receive side: fill the rx ring to exactly RX_RING_CAP, confirm the
 *     advertised window drops to 0, then drain it via tcp_recv() and confirm
 *     the existing "was==0, now>0" logic (net/tcp.c's tcp_recv()) fires an
 *     immediate window-update ACK rather than waiting on a persist timer.
 *  2. Send side: a connection whose SYN-ACK advertises a deliberately small
 *     window, confirming tcp_send()/tcp_tx_idle() throttle against that
 *     PEER-advertised window specifically (not just local ring/slot
 *     capacity, already proven by 18.4.1's max_inflight test), and that
 *     sending resumes once an ACK reopens the window.
 *
 * Same stubbing discipline as tools/tcp_reassembly_test.c: everything
 * net/tcp.c reaches outside itself is stubbed below, and the wire format is
 * independently reimplemented rather than reusing Aurora's own encoder. */
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

/* Phase 18.4.3: capture the most recent segment Aurora sent, so the test can
 * inspect fields (the advertised window, in particular) that no accessor
 * function exposes -- the same way a real peer would just look at the wire. */
static uint8_t last_sent[128];
static unsigned last_sent_len;
static unsigned send_count;

int ipv4_send(uint32_t dst, uint8_t proto, const void *payload, size_t len)
{
    (void)dst; (void)proto;
    unsigned n = (unsigned)len;
    if (n > sizeof(last_sent)) n = sizeof(last_sent);
    memcpy(last_sent, payload, n);
    last_sent_len = n;
    send_count++;
    return 0;    /* pretend every send goes out fine */
}

static uint16_t last_sent_window(void)
{
    /* struct tcp_hdr: src_port(2) dst_port(2) seq(4) ack(4) data_off(1)
     * flags(1) window(2) ... -- window sits at byte offset 14. */
    if (last_sent_len < 16) return 0xffff;
    return (uint16_t)((last_sent[14] << 8) | last_sent[15]);
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

/* Scenario 1: receive-side zero-window-then-reopen. */
static void test_receive_window(void)
{
    uint32_t peer_ip = 0x0a000002u;
    uint16_t peer_port = 9000;

    /* tcp_connect() calls our deterministic perf_now_us() stub twice (local
     * port, then iss) -- reset the counter so both are predictable here
     * regardless of what ran before this scenario. */
    fake_us = 0;
    int h = tcp_connect(peer_ip, peer_port);
    uint16_t local_port = (uint16_t)(49152 + (0 & 0x1fff));
    uint32_t our_iss = 1;
    uint32_t peer_iss = 5000;

    uint8_t seg[2048];
    unsigned n;

    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss, our_iss + 1, F_SYN | F_ACK, 65535, NULL, 0);
    tcp_input(peer_ip, seg, n);
    check("[recv] handshake reaches ESTABLISHED", tcp_state(h) == TCP_ESTABLISHED);

    /* Fill the rx ring to EXACTLY RX_RING_CAP (16384) using 1024-byte
     * in-order chunks (16 of them), so the last one lands the window on
     * precisely zero rather than merely "small." */
    uint8_t chunk[1024];
    memset(chunk, 'A', sizeof(chunk));
    uint32_t seq = peer_iss + 1;
    unsigned total = 0;
    while (total < 16384) {
        n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                     seq, our_iss + 1, F_ACK, 65535, chunk, sizeof(chunk));
        tcp_input(peer_ip, seg, n);
        seq += sizeof(chunk);
        total += sizeof(chunk);
    }
    check("[recv] rx ring filled to exactly RX_RING_CAP",
          tcp_rx_avail(h) == 16384);
    check("[recv] advertised window drops to exactly 0 once the ring is full",
          last_sent_window() == 0);

    /* Drain a modest amount -- well under the full ring -- and confirm the
     * existing was==0 && rcv_wnd>0 logic in tcp_recv() fires an immediate
     * window-update ACK advertising the newly freed space, rather than
     * silently reopening and waiting for the peer's persist timer. */
    char out[4096];
    unsigned before_sends = send_count;
    int got = tcp_recv(h, out, 2000);
    check("[recv] tcp_recv() drained the requested amount", got == 2000);
    check("[recv] draining a full window triggers an immediate ACK (not silence)",
          send_count == before_sends + 1);
    check("[recv] that immediate ACK advertises the newly freed window",
          last_sent_window() == 2000);

    /* A second drain while the window is already open should NOT trigger
     * another "reopen" ACK (there's no transition here) -- tcp_recv() only
     * sends one when moving from a genuinely zero window. */
    before_sends = send_count;
    got = tcp_recv(h, out, 500);
    check("[recv] draining a second time while already open sends no extra ACK",
          send_count == before_sends);
    (void)got;
}

/* Scenario 2: send-side respects a small PEER-advertised window. */
static void test_send_window(void)
{
    uint32_t peer_ip = 0x0a000002u;
    uint16_t peer_port = 9001;

    fake_us = 0;
    int h = tcp_connect(peer_ip, peer_port);
    uint16_t local_port = (uint16_t)(49152 + (0 & 0x1fff));
    uint32_t our_iss = 1;   /* fake_us reset above: local_port consumes 0, iss consumes 1 */
    uint32_t peer_iss = 8000;

    uint8_t seg[2048];
    unsigned n;

    /* SYN-ACK advertises a deliberately small window: 2000 bytes. */
    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss, our_iss + 1, F_SYN | F_ACK, 2000, NULL, 0);
    tcp_input(peer_ip, seg, n);
    check("[send] handshake reaches ESTABLISHED with a small peer window", tcp_state(h) == TCP_ESTABLISHED);

    uint8_t body[1400];
    memset(body, 'B', sizeof(body));

    /* First send: 1400 bytes, well within the 2000-byte peer window. */
    int sent = tcp_send(h, body, sizeof(body));
    check("[send] first 1400-byte send within a 2000-byte peer window succeeds",
          sent == (int)sizeof(body));
    check("[send] tcp_tx_idle() still true (600 bytes of window remain, but < 1400)",
          tcp_tx_idle(h) != 0);   /* room exists, even if not enough for another full 1400 */

    /* Second send: another 1400 bytes would push in-flight to 2800, past the
     * 2000-byte peer window -- must be refused even though the local
     * TCP_MAX_INFLIGHT ring (8 slots) has plenty of room. */
    sent = tcp_send(h, body, sizeof(body));
    check("[send] a second 1400-byte send is refused: it would exceed the peer's window",
          sent == -1);

    /* ACK the first segment in full, explicitly reopening the peer window
     * back to the full 2000 (peer hasn't consumed anything on its end). */
    n = build_seg(seg, g_net_config.ip, peer_ip, peer_port, local_port,
                 peer_iss + 1, our_iss + 1 + 1400, F_ACK, 2000, NULL, 0);
    tcp_input(peer_ip, seg, n);
    check("[send] tcp_tx_idle() true again once the ACK frees window room",
          tcp_tx_idle(h) != 0);

    sent = tcp_send(h, body, sizeof(body));
    check("[send] send resumes once the peer's ACK reopened the window",
          sent == (int)sizeof(body));
}

int main(void)
{
    tcp_init();
    test_receive_window();
    test_send_window();
    printf("\n18.4.3 TCP WINDOW MANAGEMENT: %s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
    return fails ? 1 : 0;
}
