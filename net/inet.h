/* Shared network helpers: byte order + IPv4 address conventions.
 *
 * The wire is big-endian ("network order"); x86 is little-endian. We keep IPv4
 * addresses in HOST order inside the stack (so comparisons and table keys are
 * plain integer ops) and convert only at the wire boundary with htonl/ntohl.
 * MAC addresses and raw frame bytes are never byte-swapped. */
#pragma once
#include <stdint.h>
#include "netcfg.h"

static inline uint16_t htons(uint16_t x) { return (uint16_t)((x << 8) | (x >> 8)); }
static inline uint16_t ntohs(uint16_t x) { return htons(x); }
static inline uint32_t htonl(uint32_t x)
{
    return ((x & 0x000000ffu) << 24) | ((x & 0x0000ff00u) << 8)
         | ((x & 0x00ff0000u) >> 8)  | ((x & 0xff000000u) >> 24);
}
static inline uint32_t ntohl(uint32_t x) { return htonl(x); }

/* Build a host-order IPv4 address from dotted octets. */
#define IP4(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* Live network configuration (net/netcfg.c): the QEMU SLIRP static defaults
 * until a DHCP lease (net/dhcp.c, Phase 15.3) overwrites them. */
#define IP_LOCAL      (g_net_config.ip)
#define IP_GATEWAY    (g_net_config.gateway)
#define IP_BROADCAST  IP4(255, 255, 255, 255)

/* EtherTypes (host order; htons() at the wire). */
#define ETH_P_IPV4  0x0800
#define ETH_P_ARP   0x0806

/* IPv4 protocol numbers. */
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17

/* Monotonic milliseconds since boot (PIT is 100 Hz -> 10 ms/tick). */
uint64_t net_now_ms(void);

/* Internet checksum (RFC 1071): one's-complement sum over `len` bytes. Compute
 * with the checksum field zeroed and store the result directly; verify by
 * summing the whole structure and checking the result is 0. */
uint16_t inet_csum(const void *data, uint32_t len);
