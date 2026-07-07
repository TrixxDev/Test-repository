/* UDP datagrams + port demux — see udp.h. */
#include "udp.h"
#include "ipv4.h"
#include "inet.h"
#include "string.h"

struct udp_hdr {
    uint16_t src_port;      /* network order */
    uint16_t dst_port;
    uint16_t len;           /* header + data */
    uint16_t checksum;      /* 0 = none (optional over IPv4) */
} __attribute__((packed));

#define UDP_MAX_BINDS   16
#define UDP_MAX_DATA    1472    /* 1500 MTU - 20 IPv4 - 8 UDP */

struct binding {
    uint16_t      port;
    udp_handler_t handler;
};

static struct binding binds[UDP_MAX_BINDS];
static uint8_t        udp_tx[sizeof(struct udp_hdr) + UDP_MAX_DATA];

void udp_init(void)
{
    memset(binds, 0, sizeof(binds));
}

int udp_bind(uint16_t port, udp_handler_t handler)
{
    if (port == 0 || !handler)
        return -1;
    int free_slot = -1;
    for (int i = 0; i < UDP_MAX_BINDS; i++) {
        if (binds[i].handler && binds[i].port == port) {  /* replace */
            binds[i].handler = handler;
            return 0;
        }
        if (!binds[i].handler && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        return -1;                                          /* table full */
    binds[free_slot].port    = port;
    binds[free_slot].handler = handler;
    return 0;
}

int udp_send(uint32_t dst, uint16_t src_port, uint16_t dst_port,
             const void *payload, size_t len)
{
    if (len > UDP_MAX_DATA)
        return -1;

    struct udp_hdr *h = (struct udp_hdr *)udp_tx;
    unsigned total = sizeof(*h) + (unsigned)len;
    h->src_port = htons(src_port);
    h->dst_port = htons(dst_port);
    h->len      = htons((uint16_t)total);
    h->checksum = 0;                                        /* optional: none */
    if (len)
        memcpy(udp_tx + sizeof(*h), payload, len);

    return ipv4_send(dst, IPPROTO_UDP, udp_tx, total);
}

void udp_input(uint32_t src, const void *segment, size_t len)
{
    if (len < sizeof(struct udp_hdr))
        return;
    const struct udp_hdr *h = (const struct udp_hdr *)segment;

    unsigned ulen = ntohs(h->len);
    if (ulen < sizeof(struct udp_hdr) || ulen > len)
        return;                                             /* malformed length */

    uint16_t dport = ntohs(h->dst_port);
    uint16_t sport = ntohs(h->src_port);
    const uint8_t *data = (const uint8_t *)segment + sizeof(struct udp_hdr);
    unsigned dlen = ulen - sizeof(struct udp_hdr);

    for (int i = 0; i < UDP_MAX_BINDS; i++) {
        if (binds[i].handler && binds[i].port == dport) {
            binds[i].handler(src, sport, data, dlen);
            return;
        }
    }
    /* No listener: silently drop (a real stack would send ICMP port-unreach). */
}
