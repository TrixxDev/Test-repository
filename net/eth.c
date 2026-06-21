/* Ethernet II framing + EtherType dispatch — see eth.h. */
#include "eth.h"
#include "inet.h"
#include "arp.h"
#include "virtio_net.h"
#include "string.h"

const uint8_t eth_broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* One static staging buffer: assembling a frame here and handing it to the
 * transport keeps the protocol layers allocation-free (they run in polled
 * context, never re-entrant). */
static uint8_t txframe[ETH_HLEN + 1500];

int eth_send(const uint8_t *dst, uint16_t type, const void *payload, size_t len)
{
    if (!dst || len > sizeof(txframe) - ETH_HLEN)
        return -1;

    struct eth_hdr *h = (struct eth_hdr *)txframe;
    memcpy(h->dst, dst, ETH_ALEN);
    memcpy(h->src, virtio_net_mac(), ETH_ALEN);
    h->type = htons(type);
    if (len)
        memcpy(txframe + ETH_HLEN, payload, len);

    /* Pad runts up to the 60-byte Ethernet minimum so net_send_frame()
     * (which rejects < 14) and SLIRP both accept them. */
    unsigned flen = ETH_HLEN + (unsigned)len;
    if (flen < 60) {
        memset(txframe + flen, 0, 60 - flen);
        flen = 60;
    }
    return net_send_frame(txframe, flen);
}

void eth_input(const void *frame, size_t len)
{
    if (len < ETH_HLEN)
        return;                         /* too short to hold a header */

    const struct eth_hdr *h = (const struct eth_hdr *)frame;
    const uint8_t *payload = (const uint8_t *)frame + ETH_HLEN;
    size_t plen = len - ETH_HLEN;

    switch (ntohs(h->type)) {
    case ETH_P_ARP:
        arp_input(payload, plen);
        break;
    case ETH_P_IPV4:
        /* Phase 6: ipv4_input(payload, plen); */
        break;
    default:
        break;                          /* unknown EtherType: ignore */
    }
}
