/* DNS resolver over UDP — Phase 7.5. Caching — Phase 15.6.
 *
 * The API is typed from the start (dns_query takes a record type) so adding
 * AAAA/CNAME later won't break callers, even though only A is parsed today.
 * Queries go to the SLIRP virtual DNS server (10.0.2.3:53), which forwards to
 * the host's resolver. Synchronous: dns_query() sends and pumps the RX path
 * until the answer arrives or it times out -- unless the answer is already
 * cached, in which case it returns immediately with no network traffic. */
#pragma once
#include <stdint.h>

/* DNS record types (RFC 1035 + AAAA). */
#define DNS_A       1
#define DNS_NS      2
#define DNS_CNAME   5
#define DNS_AAAA    28

/* Resolve `name` for record `type`. For DNS_A, *out_ip is filled (host order) on
 * success. Returns 0 on success, -1 on timeout / no matching record / error.
 * DNS_A lookups are cached (positive and negative, see below); other types
 * are never cached (nothing else is actually resolved yet). */
int dns_query(const char *name, uint16_t type, uint32_t *out_ip);

/* --- DNS cache (Phase 15.6): pure, host-testable slot logic --- */

#define DNS_CACHE_SIZE       16
#define DNS_CACHE_NAME_MAX   128
#define DNS_CACHE_TTL_MIN_MS (5u    * 1000u)  /* floor: a near-zero TTL would cause query storms */
#define DNS_CACHE_TTL_MAX_MS (3600u * 1000u)  /* ceiling: don't trust a huge/misconfigured TTL forever */
#define DNS_CACHE_NEG_TTL_MS (10u   * 1000u)  /* negative (failed lookup) cache lifetime */

typedef enum { DNS_CACHE_EMPTY = 0, DNS_CACHE_POSITIVE, DNS_CACHE_NEGATIVE } dns_cache_state;

typedef struct {
    char            name[DNS_CACHE_NAME_MAX];
    uint32_t        ip;             /* valid only when state == DNS_CACHE_POSITIVE */
    uint64_t        expires_ms;
    dns_cache_state state;
} dns_cache_slot;

/* Clamp a DNS answer's TTL (seconds, as carried on the wire) to a sane
 * cacheable lifetime in milliseconds. */
uint32_t dns_cache_clamp_ttl_ms(uint32_t ttl_secs);

/* Case-insensitive hostname equality (RFC 4343: DNS names aren't case-sensitive). */
int dns_name_eq(const char *a, const char *b);

/* Find a live entry for `name` in cache[0..n), lazily expiring it in place
 * (the same idiom as arp.c's cache) if its TTL has passed. Returns NULL if
 * there's no live entry. Pure: takes `now_ms` explicitly rather than
 * reading the clock, so it's testable without a network/time stub. */
dns_cache_slot *dns_cache_find(dns_cache_slot *cache, int n, const char *name, uint64_t now_ms);

/* The slot to (re)populate for `name`: its own existing entry if it has one
 * (even expired -- about to be overwritten anyway), else a free slot, else
 * the soonest-to-expire one (evicted to make room). */
dns_cache_slot *dns_cache_slot_for(dns_cache_slot *cache, int n, const char *name);

/* Populate `slot` as a positive/negative entry for `name`. A zero TTL means
 * "do not cache this answer" (RFC 1035) and leaves `slot` untouched. */
void dns_cache_put_positive(dns_cache_slot *slot, const char *name, uint32_t ip, uint32_t ttl_secs, uint64_t now_ms);
void dns_cache_put_negative(dns_cache_slot *slot, const char *name, uint64_t now_ms);
