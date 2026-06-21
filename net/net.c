/* Network glue: time base, the RX pump, and the Phase 4/5/6 self-test. */
#include "netstack.h"
#include "inet.h"
#include "eth.h"
#include "arp.h"
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "dns.h"
#include "tcp.h"
#include "virtio_net.h"
#include "pit.h"
#include "perf.h"
#include "string.h"
#include "kio.h"

uint64_t net_now_ms(void) { return (uint64_t)pit_ticks() * 10; }

uint16_t inet_csum(const void *data, uint32_t len)
{
    const uint16_t *w = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *w++; len -= 2; }
    if (len) sum += *(const uint8_t *)w;          /* odd trailing byte */
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void net_init(void) { arp_init(); ipv4_init(); udp_init(); tcp_init(); }

/* Drain every pending RX frame up into the dispatcher. */
void net_poll(void)
{
    uint8_t frame[1600];
    int n;
    while ((n = net_recv_frame(frame, sizeof(frame))) > 0)
        eth_input(frame, (size_t)n);
}

/* Poll the wire until `ip` resolves in the cache, or `timeout_ms` elapses. */
static int wait_resolved(uint32_t ip, uint8_t mac[6], unsigned timeout_ms)
{
    uint64_t deadline = net_now_ms() + timeout_ms;
    while (net_now_ms() < deadline) {
        net_poll();
        if (arp_lookup(ip, mac))
            return 1;
        __asm__ volatile("" ::: "memory");
    }
    return 0;
}

#define OCTETS(ip) (unsigned)(((ip) >> 24) & 0xff), (unsigned)(((ip) >> 16) & 0xff), \
                   (unsigned)(((ip) >> 8) & 0xff),  (unsigned)((ip) & 0xff)

/* Phase 7: a UDP echo handler for the self-test. Logs the datagram and echoes
 * it back to the sender, so the host's nc sees a reply too. */
#define UDP_TEST_PORT 9999
#define TCP_TEST_PORT 80
static volatile int udp_rx_count;
static void udp_test_handler(uint32_t src, uint16_t sport, const void *data, size_t len)
{
    char tmp[64];
    unsigned n = (unsigned)len < sizeof(tmp) - 1 ? (unsigned)len : sizeof(tmp) - 1;
    memcpy(tmp, data, n);
    tmp[n] = '\0';
    kprintf("[udp] rx %u bytes from %u.%u.%u.%u:%u: \"%s\"\n",
            (unsigned)len, OCTETS(src), sport, tmp);
    udp_rx_count++;
    udp_send(src, UDP_TEST_PORT, sport, data, len);     /* echo back */
}

/* Phase 6 milestone: ping `dst` `count` times, reporting RTT per reply. Drives
 * the whole stack (Ethernet/ARP/IPv4/ICMP/checksum) in one round-trip each.
 * Returns the number of replies received. */
static int net_ping(uint32_t dst, int count)
{
    const char data[] = "AuroraOS-ping";
    const uint16_t id = 0xAE01;
    int recv = 0;

    kprintf("[icmp] PING %u.%u.%u.%u : %d packets\n", OCTETS(dst), count);
    for (int i = 1; i <= count; i++) {
        uint16_t seq = (uint16_t)i;

        /* Send; retry while the next-hop ARP entry is still resolving. */
        int sent = -1;
        uint32_t t0 = (uint32_t)perf_now_us();
        uint64_t sdl = net_now_ms() + 2000;
        while (net_now_ms() < sdl) {
            t0 = (uint32_t)perf_now_us();
            sent = icmp_send_echo(dst, id, seq, data, sizeof(data) - 1);
            if (sent == 0)
                break;
            net_poll();                         /* let the ARP reply land */
        }
        if (sent != 0) {
            kprintf("[icmp] seq=%d: send failed (no route)\n", i);
            continue;
        }

        /* Await the matching echo reply. */
        int got = 0;
        uint32_t rtt = 0;
        uint64_t dl = net_now_ms() + 1000;
        while (net_now_ms() < dl) {
            net_poll();
            if (icmp_take_reply(id, seq)) {
                rtt = (uint32_t)perf_now_us() - t0;
                got = 1;
                break;
            }
        }
        if (got) {
            recv++;
            kprintf("[icmp] reply from %u.%u.%u.%u: seq=%d time=%u us\n",
                    OCTETS(dst), i, rtt);
        } else {
            kprintf("[icmp] seq=%d: request timed out\n", i);
        }
    }
    kprintf("[icmp] %d/%d replies received -- %s\n", recv, count,
            recv == count ? "PING OK" : (recv ? "partial" : "PING FAIL"));
    return recv;
}

/* Phase 4 (Ethernet) + Phase 5 (ARP) proof. Three scenarios the user specified
 * must pass before IPv4:
 *   1. who-has the gateway -> reply learned;
 *   2. a repeat lookup is served from the cache without touching the wire;
 *   3. after expiry the entry is gone and a fresh request goes out.
 * Scenario 3 forces expiry via a test hook rather than sleeping 60 s. */
void net_selftest(void)
{
    if (!virtio_net_present()) {
        kprintf("[net] selftest skipped (no NIC)\n");
        return;
    }

    uint8_t mac[6];
    struct net_stats s0, s1;

    /* (1) Resolve the gateway. */
    kprintf("[arp] (1) who-has %u.%u.%u.%u\n", OCTETS(IP_GATEWAY));
    arp_resolve(IP_GATEWAY, mac);
    if (!wait_resolved(IP_GATEWAY, mac, 2000)) {
        kprintf("[arp] (1) FAIL: no reply (timeout)\n");
        return;
    }
    kprintf("[arp] (1) resolved -> %x:%x:%x:%x:%x:%x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    /* (2) Repeat: must come from the cache with no extra TX. */
    net_get_stats(&s0);
    int hit = arp_lookup(IP_GATEWAY, mac);
    int r2  = arp_resolve(IP_GATEWAY, mac);
    net_get_stats(&s1);
    kprintf("[arp] (2) cache lookup=%d resolve=%d, tx %u->%u (%s)\n",
            hit, r2, s0.tx_packets, s1.tx_packets,
            (hit && r2 && s0.tx_packets == s1.tx_packets) ? "cache hit, no wire" : "FAIL");

    /* (3) Force expiry: the entry must vanish and a fresh request go out. */
    arp_test_expire_all();
    int stale = arp_lookup(IP_GATEWAY, mac);    /* expect 0 */
    net_get_stats(&s0);
    arp_resolve(IP_GATEWAY, mac);               /* should send a new request */
    int ok = wait_resolved(IP_GATEWAY, mac, 2000);
    net_get_stats(&s1);
    kprintf("[arp] (3) post-expiry lookup=%d, re-resolved=%d, tx %u->%u (%s)\n",
            stale, ok, s0.tx_packets, s1.tx_packets,
            (stale == 0 && ok && s1.tx_packets > s0.tx_packets) ? "expired -> re-asked" : "FAIL");

    /* Phase 6: ping the gateway. The headline milestone. */
    net_ping(IP_GATEWAY, 4);

    /* Phase 7: UDP. Fire a datagram at the host (10.0.2.2:9999) and listen for a
     * reply on the same port. With `nc -u -l 9999` (or the udptest harness) on
     * the host, this proves both UDP TX and RX through SLIRP's NAT. */
    udp_bind(UDP_TEST_PORT, udp_test_handler);
    const char hello[] = "hello from aurora\n";
    kprintf("[udp] send \"hello from aurora\" -> %u.%u.%u.%u:%u\n",
            OCTETS(IP_GATEWAY), UDP_TEST_PORT);
    udp_send(IP_GATEWAY, UDP_TEST_PORT, UDP_TEST_PORT, hello, sizeof(hello) - 1);
    uint64_t udl = net_now_ms() + 4000;
    while (net_now_ms() < udl)
        net_poll();
    kprintf("[udp] %d datagram(s) received -- %s\n", udp_rx_count,
            udp_rx_count ? "UDP RX OK" : "no reply (TX is proven via pcap)");

    /* Phase 7.5: DNS over UDP, then ping by hostname. The first user-visible
     * leap -- the OS resolves a real name on its own. */
    const char *host = "example.com";
    uint32_t hip = 0;
    if (dns_query(host, DNS_A, &hip) == 0) {
        kprintf("[dns] %s -> %u.%u.%u.%u\n", host, OCTETS(hip));
        kprintf("[ping] %s\n", host);
        if (net_ping(hip, 2) == 0)
            kprintf("[ping] %s: no reply -- outbound ICMP to the internet needs an "
                    "open network policy; the gateway ping above proves the path\n", host);
    } else {
        kprintf("[dns] %s: no answer (query sent; see pcap / network policy)\n", host);
    }

    /* Phase 8.1: TCP three-way handshake (client connect only). Needs a TCP
     * service reachable at 10.0.2.2:TCP_TEST_PORT (the tcptest.py harness, or any
     * host listener); without one, SLIRP RSTs and the state goes to CLOSED. */
    kprintf("[tcp] connect %u.%u.%u.%u:%d\n", OCTETS(IP_GATEWAY), TCP_TEST_PORT);
    tcp_connect(IP_GATEWAY, TCP_TEST_PORT);
    uint64_t cdl = net_now_ms() + 4000;
    while (net_now_ms() < cdl &&
           tcp_state() != TCP_ESTABLISHED && tcp_state() != TCP_CLOSED)
        net_poll();
    kprintf("[tcp] state=%s -- %s\n", tcp_state_name(tcp_state()),
            tcp_state() == TCP_ESTABLISHED ? "HANDSHAKE OK" : "no connection");

    net_get_stats(&s1);
    kprintf("[net] ipv4 rx_ok=%u rx_drop=%u; stats rx=%u/%u tx=%u/%u drop=%u/%u err=%u/%u irq=%u\n",
            ipv4_rx_ok(), ipv4_rx_dropped(),
            s1.rx_packets, s1.rx_bytes, s1.tx_packets, s1.tx_bytes,
            s1.rx_dropped, s1.tx_dropped, s1.rx_errors, s1.tx_errors, s1.rx_irqs);
}
