/* IPv4 RX validation + TX assembly — see ipv4.h. */
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "eth.h"
#include "arp.h"
#include "inet.h"
#include "string.h"

#define IPV4_VERSION    4
#define IPV4_IHL_MIN    5           /* 5 * 4 = 20-byte header, no options */
#define IPV4_TTL        64
#define FRAG_MASK       0x3fff      /* MF bit | fragment offset (DF ignored) */

static uint16_t  ip_id;             /* outgoing identification counter */
static unsigned  rx_ok, rx_drop;
static uint8_t   ip_tx[1500];       /* staging: [ipv4 hdr][payload] */

void ipv4_init(void) { ip_id = 0; rx_ok = 0; rx_drop = 0; }

unsigned ipv4_rx_ok(void)      { return rx_ok; }
unsigned ipv4_rx_dropped(void) { return rx_drop; }

/* Next hop for `dst` (host order): on-link addresses go direct, everything else
 * via the gateway. Our network is a /24 (SLIRP 10.0.2.0/24). */
static uint32_t next_hop(uint32_t dst)
{
    if ((dst & 0xffffff00u) == (IP_LOCAL & 0xffffff00u))
        return dst;
    return IP_GATEWAY;
}

void ipv4_input(const void *packet, size_t len)
{
    if (len < sizeof(struct ipv4_hdr)) { rx_drop++; return; }
    const struct ipv4_hdr *h = (const struct ipv4_hdr *)packet;

    uint8_t version = h->ver_ihl >> 4;
    uint8_t ihl     = h->ver_ihl & 0x0f;
    if (version != IPV4_VERSION || ihl < IPV4_IHL_MIN) { rx_drop++; return; }

    unsigned hlen = (unsigned)ihl * 4;
    unsigned total = ntohs(h->total_len);
    if (hlen > len || total < hlen || total > len) { rx_drop++; return; }

    if (ntohs(h->frag_off) & FRAG_MASK) { rx_drop++; return; }   /* fragments: drop */

    if (inet_csum(h, hlen) != 0) { rx_drop++; return; }          /* bad checksum */

    if (ntohl(h->dst) != IP_LOCAL) { rx_drop++; return; }        /* not for us */

    rx_ok++;
    const uint8_t *payload = (const uint8_t *)packet + hlen;
    unsigned plen = total - hlen;
    uint32_t src = ntohl(h->src);

    switch (h->proto) {
    case IPPROTO_ICMP:
        icmp_input(src, payload, plen);
        break;
    case IPPROTO_UDP:
        udp_input(src, payload, plen);
        break;
    default:
        break;
    }
}

int ipv4_send(uint32_t dst, uint8_t proto, const void *payload, size_t len)
{
    if (len > sizeof(ip_tx) - sizeof(struct ipv4_hdr))
        return -1;

    uint8_t mac[6];
    if (!arp_resolve(next_hop(dst), mac))
        return -1;                              /* E_PENDING: ARP in flight */

    struct ipv4_hdr *h = (struct ipv4_hdr *)ip_tx;
    unsigned total = sizeof(struct ipv4_hdr) + (unsigned)len;
    h->ver_ihl   = (IPV4_VERSION << 4) | IPV4_IHL_MIN;
    h->tos       = 0;
    h->total_len = htons((uint16_t)total);
    h->id        = htons(ip_id++);
    h->frag_off  = 0;                           /* no fragmentation */
    h->ttl       = IPV4_TTL;
    h->proto     = proto;
    h->checksum  = 0;
    h->src       = htonl(IP_LOCAL);
    h->dst       = htonl(dst);
    h->checksum  = inet_csum(h, sizeof(struct ipv4_hdr));

    if (len)
        memcpy(ip_tx + sizeof(struct ipv4_hdr), payload, len);

    return eth_send(mac, ETH_P_IPV4, ip_tx, total);
}
