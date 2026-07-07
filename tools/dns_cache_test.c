/* Host-side DNS cache tests (net/dns.c): pure slot find/allocate/populate
 * logic and TTL clamping, no UDP, no wall clock, no QEMU -- the same
 * separation as net/dhcp.c between "pure" (host-testable) and "live
 * transaction" (kernel-only). Build/run: `make dns-cache-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "dns.h"
#include "udp.h"
#include "netstack.h"
#include "inet.h"

/* Test doubles: dns_query()'s live transaction references these, but nothing
 * in this file calls it -- only the pure cache functions are under test.
 * net/dns.c is one translation unit, so the linker still needs them resolved. */
int udp_bind(uint16_t port, udp_handler_t handler) { (void)port; (void)handler; return 0; }
int udp_send(uint32_t dst, uint16_t sp, uint16_t dp, const void *payload, size_t len)
{ (void)dst; (void)sp; (void)dp; (void)payload; (void)len; return -1; }
void net_poll(void) {}
uint64_t net_now_ms(void) { return 0; }
void kprintf(const char *fmt, ...) { (void)fmt; }

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

int main(void)
{
    /* --- dns_name_eq: case-insensitive, RFC 4343 --- */
    check_ok("name_eq: identical", dns_name_eq("example.com", "example.com"));
    check_ok("name_eq: case-insensitive", dns_name_eq("Example.COM", "example.com"));
    check_ok("name_eq: different names", !dns_name_eq("example.com", "example.org"));
    check_ok("name_eq: prefix isn't equality", !dns_name_eq("example.com", "example.com.evil"));

    /* --- dns_cache_clamp_ttl_ms --- */
    check_ok("clamp: typical TTL passes through", dns_cache_clamp_ttl_ms(300) == 300000u);
    check_ok("clamp: near-zero TTL floored", dns_cache_clamp_ttl_ms(1) == DNS_CACHE_TTL_MIN_MS);
    check_ok("clamp: zero TTL floored too (caller decides whether to cache at all)",
             dns_cache_clamp_ttl_ms(0) == DNS_CACHE_TTL_MIN_MS);
    check_ok("clamp: huge TTL capped", dns_cache_clamp_ttl_ms(1000000) == DNS_CACHE_TTL_MAX_MS);
    check_ok("clamp: exactly at the ceiling", dns_cache_clamp_ttl_ms(3600) == DNS_CACHE_TTL_MAX_MS);

    /* --- dns_cache_find / dns_cache_slot_for / put_positive / put_negative --- */
    {
        dns_cache_slot cache[4];
        memset(cache, 0, sizeof cache);

        check_ok("find: empty cache misses", dns_cache_find(cache, 4, "example.com", 1000) == 0);

        dns_cache_slot *s = dns_cache_slot_for(cache, 4, "example.com");
        check_ok("slot_for: picks a free slot when empty", s == &cache[0]);
        dns_cache_put_positive(s, "example.com", IP4(93, 184, 216, 34), 300, 1000);
        check_ok("put_positive: state is POSITIVE", cache[0].state == DNS_CACHE_POSITIVE);
        check_ok("put_positive: name stored", dns_name_eq(cache[0].name, "example.com"));
        check_ok("put_positive: ip stored", cache[0].ip == IP4(93, 184, 216, 34));
        check_ok("put_positive: expiry is now + clamped ttl", cache[0].expires_ms == 1000 + 300000u);

        dns_cache_slot *hit = dns_cache_find(cache, 4, "EXAMPLE.COM", 1000);
        check_ok("find: case-insensitive hit right after storing", hit == &cache[0]);
        check_ok("find: hit is POSITIVE with the right ip", hit && hit->state == DNS_CACHE_POSITIVE && hit->ip == IP4(93,184,216,34));

        check_ok("find: still live just before expiry", dns_cache_find(cache, 4, "example.com", 1000 + 300000u - 1) != 0);
        check_ok("find: expired exactly at expiry (lazily demoted)", dns_cache_find(cache, 4, "example.com", 1000 + 300000u) == 0);
        check_ok("find: demotion actually cleared the slot's state", cache[0].state == DNS_CACHE_EMPTY);

        /* re-populate for the negative-cache tests */
        s = dns_cache_slot_for(cache, 4, "nx.example.com");
        dns_cache_put_negative(s, "nx.example.com", 5000);
        check_ok("put_negative: state is NEGATIVE", s->state == DNS_CACHE_NEGATIVE);
        check_ok("put_negative: expiry is now + fixed negative ttl", s->expires_ms == 5000 + DNS_CACHE_NEG_TTL_MS);
        dns_cache_slot *nhit = dns_cache_find(cache, 4, "nx.example.com", 5000);
        check_ok("find: negative hit returns the slot (caller checks state)", nhit == s);
        check_ok("find: negative entry expires too",
                 dns_cache_find(cache, 4, "nx.example.com", 5000 + DNS_CACHE_NEG_TTL_MS) == 0);
    }

    /* --- slot_for: reuse-own-entry vs free-slot vs eviction --- */
    {
        dns_cache_slot cache[2];
        memset(cache, 0, sizeof cache);
        dns_cache_put_positive(dns_cache_slot_for(cache, 2, "a.example"), "a.example", IP4(1,1,1,1), 100, 0);
        dns_cache_put_positive(dns_cache_slot_for(cache, 2, "b.example"), "b.example", IP4(2,2,2,2), 200, 0);
        /* cache is full (2/2); re-querying "a.example" must reuse ITS OWN slot, not evict "b" */
        dns_cache_slot *s = dns_cache_slot_for(cache, 2, "a.example");
        check_ok("slot_for: refreshing an existing name reuses its own slot", s == &cache[0]);
        check_ok("slot_for: the other entry (b.example) is untouched",
                 cache[1].state == DNS_CACHE_POSITIVE && dns_name_eq(cache[1].name, "b.example"));

        /* a genuinely new name when full must evict the soonest-to-expire entry */
        s = dns_cache_slot_for(cache, 2, "c.example");
        check_ok("slot_for: full cache evicts the soonest-to-expire slot (a.example, ttl=100 < b's 200)",
                 s == &cache[0]);
    }

    printf(failures ? "\nDNS CACHE TEST: %d FAILURE(S)\n" : "\nDNS CACHE TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
