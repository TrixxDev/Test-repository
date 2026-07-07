/* Ethernet II framing — Phase 4.
 *
 * The single seam between the virtio-net transport (raw frames) and the protocol
 * logic above (ARP, IPv4, ...). Outbound: eth_send() prepends the 14-byte header
 * and hands the frame to net_send_frame(). Inbound: eth_input() parses the header
 * and dispatches by EtherType. Adding IPv6 later is a new case here and nothing
 * in the driver changes. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define ETH_ALEN   6        /* MAC address length      */
#define ETH_HLEN   14       /* dst(6) + src(6) + type(2) */

struct eth_hdr {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t type;          /* network order on the wire */
} __attribute__((packed));

/* Broadcast MAC (ff:ff:ff:ff:ff:ff). */
extern const uint8_t eth_broadcast[ETH_ALEN];

/* Send one frame: prepend the header (src = our MAC) and transmit `len` payload
 * bytes of EtherType `type` (host order) to `dst`. Returns 0 on success. */
int  eth_send(const uint8_t *dst, uint16_t type, const void *payload, size_t len);

/* Dispatch one received frame (header included) to the right protocol handler. */
void eth_input(const void *frame, size_t len);
