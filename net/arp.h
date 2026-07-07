/* ARP (Address Resolution Protocol) — Phase 5.
 *
 * A real cache + state machine, not a one-shot "enough for ping". IPv4 (and
 * later TCP) call arp_resolve(ip, mac) and never need to know whether the MAC is
 * already known, still being asked for, or expired — the cache hides all of it.
 *
 *   ARP_EMPTY    no entry / expired      -> arp_resolve() sends a request
 *   ARP_PENDING  request sent, awaiting  -> arp_resolve() returns "not yet"
 *   ARP_RESOLVED MAC known, within TTL   -> arp_resolve() returns the MAC
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define ARP_CACHE_SIZE  32
#define ARP_TTL_MS      60000u      /* resolved entries live 60 s */

typedef enum {
    ARP_EMPTY = 0,
    ARP_PENDING,
    ARP_RESOLVED,
} arp_state_t;

typedef struct {
    uint32_t    ip;             /* host order */
    uint8_t     mac[6];
    uint64_t    expires;        /* ms (RESOLVED: TTL; PENDING: retry deadline) */
    arp_state_t state;
} arp_entry_t;

void arp_init(void);

/* Handle one received ARP packet (Ethernet payload, header stripped). Learns the
 * sender and replies if it is a request for our IP. */
void arp_input(const void *payload, size_t len);

/* Pure cache lookup: returns 1 and fills mac_out if `ip` is RESOLVED and within
 * its TTL; 0 otherwise. Never touches the wire. */
int  arp_lookup(uint32_t ip, uint8_t mac_out[6]);

/* Resolve `ip` to a MAC. Returns 1 (resolved, mac_out filled) or 0 (a request
 * was sent / is in flight — try again later). This is the API IPv4 uses. */
int  arp_resolve(uint32_t ip, uint8_t mac_out[6]);

/* Broadcast a who-has request for `ip`. */
void arp_request(uint32_t ip);

/* Diagnostics: number of RESOLVED (unexpired) entries. */
int  arp_cache_count(void);

/* Test hook: force every entry to expire now (exercises the expiry path without
 * sleeping 60 s). */
void arp_test_expire_all(void);
