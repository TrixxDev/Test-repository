/* IPv4 — Phase 6 (deliberately minimal).
 *
 * RX accepts ONLY: version 4, IHL >= 5, not a fragment, valid header checksum,
 * destination == our IP. Everything else is dropped. TX builds just a 20-byte
 * header + payload + checksum: no options, no fragmentation, no broadcast or
 * multicast routing. Next hop is resolved through arp_resolve(), so the IP layer
 * never touches the ARP cache directly. */
#pragma once
#include <stdint.h>
#include <stddef.h>

struct ipv4_hdr {
    uint8_t  ver_ihl;       /* 0x45 = version 4, 5 words (20 bytes) */
    uint8_t  tos;
    uint16_t total_len;     /* header + payload (network order) */
    uint16_t id;
    uint16_t frag_off;      /* must be a non-fragment (offset 0, MF clear) */
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;           /* network order */
    uint32_t dst;           /* network order */
} __attribute__((packed));

void ipv4_init(void);

/* Parse + validate one IPv4 packet (Ethernet payload) and dispatch by protocol. */
void ipv4_input(const void *packet, size_t len);

/* Send `len` bytes of `payload` as protocol `proto` to host-order `dst`. Resolves
 * the next hop via ARP; returns 0 on success, -1 if ARP is not ready yet
 * (E_PENDING) or on error. The caller retries when it's pending. */
int  ipv4_send(uint32_t dst, uint8_t proto, const void *payload, size_t len);

/* Diagnostics. */
unsigned ipv4_rx_ok(void);
unsigned ipv4_rx_dropped(void);
