/* DNS resolver over UDP — see dns.h. */
#include "dns.h"
#include "udp.h"
#include "netstack.h"
#include "inet.h"
#include "netcfg.h"
#include "string.h"
#include "kio.h"

#define IP_DNS          (g_net_config.dns[0])   /* live config: static default, or a DHCP lease */
#define DNS_PORT        53
#define DNS_CLIENT_PORT 50053               /* our ephemeral source port */

#define OCTETS(ip) (unsigned)(((ip) >> 24) & 0xff), (unsigned)(((ip) >> 16) & 0xff), \
                   (unsigned)(((ip) >> 8) & 0xff),  (unsigned)((ip) & 0xff)

struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount, ancount, nscount, arcount;
} __attribute__((packed));

/* Response capture (filled by the UDP handler). */
static volatile int      resp_have;
static volatile unsigned resp_len;
static uint8_t           resp_buf[512];
static uint16_t          query_id;

static void dns_handler(uint32_t src, uint16_t sport, const void *data, size_t len)
{
    (void)src; (void)sport;
    unsigned n = len < sizeof(resp_buf) ? (unsigned)len : sizeof(resp_buf);
    memcpy(resp_buf, data, n);
    resp_len  = n;
    resp_have = 1;
}

/* Encode "a.b.c" as length-prefixed labels terminated by 0. Returns bytes
 * written, or -1 on a malformed name. */
static int encode_qname(uint8_t *out, const char *name)
{
    int o = 0;
    const char *p = name;
    while (*p) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        int label = (int)(dot - p);
        if (label <= 0 || label > 63)
            return -1;
        out[o++] = (uint8_t)label;
        for (int i = 0; i < label; i++)
            out[o++] = (uint8_t)p[i];
        p = (*dot == '.') ? dot + 1 : dot;
    }
    out[o++] = 0;
    return o;
}

/* Skip a (possibly compressed) name in the message, returning the position just
 * past it. */
static const uint8_t *skip_name(const uint8_t *p, const uint8_t *end)
{
    while (p < end) {
        uint8_t b = *p;
        if (b == 0)
            return p + 1;
        if ((b & 0xc0) == 0xc0)         /* compression pointer: 2 bytes */
            return p + 2;
        p += 1 + b;                     /* a label */
    }
    return end;
}

/* Fills *out_ttl (seconds, as carried on the wire) alongside *out_ip on a
 * matching answer, so the caller can decide how long to cache it. */
static int parse_response(uint16_t type, uint32_t *out_ip, uint32_t *out_ttl)
{
    const uint8_t *m = resp_buf;
    unsigned mlen = resp_len;
    if (mlen < sizeof(struct dns_hdr))
        return -1;

    const struct dns_hdr *h = (const struct dns_hdr *)m;
    if (ntohs(h->id) != query_id)
        return -1;
    uint16_t flags = ntohs(h->flags);
    if (!(flags & 0x8000) || (flags & 0x000f))   /* must be a response, rcode 0 */
        return -1;

    uint16_t qd = ntohs(h->qdcount);
    uint16_t an = ntohs(h->ancount);
    const uint8_t *p   = m + sizeof(*h);
    const uint8_t *end = m + mlen;

    for (int i = 0; i < qd; i++) {       /* skip the echoed question(s) */
        p = skip_name(p, end);
        p += 4;                          /* QTYPE + QCLASS */
    }

    for (int i = 0; i < an && p + 10 <= end; i++) {
        p = skip_name(p, end);
        if (p + 10 > end)
            break;
        uint16_t atype = (uint16_t)((p[0] << 8) | p[1]);
        uint32_t ttl   = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                          ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        uint16_t rdlen = (uint16_t)((p[8] << 8) | p[9]);
        p += 10;
        if (p + rdlen > end)
            break;
        if (atype == DNS_A && rdlen == 4 && (type == DNS_A)) {
            if (out_ip)
                *out_ip = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                          ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
            if (out_ttl) *out_ttl = ttl;
            return 0;
        }
        p += rdlen;
    }
    return -1;                           /* no matching record */
}

/* ---- DNS cache (Phase 15.6): pure slot logic, see dns.h ---- */

int dns_name_eq(const char *a, const char *b)
{
    while (*a && *b) {
        int x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
        a++; b++;
    }
    return *a == *b;
}

uint32_t dns_cache_clamp_ttl_ms(uint32_t ttl_secs)
{
    uint64_t ms = (uint64_t)ttl_secs * 1000u;
    if (ms < DNS_CACHE_TTL_MIN_MS) ms = DNS_CACHE_TTL_MIN_MS;
    if (ms > DNS_CACHE_TTL_MAX_MS) ms = DNS_CACHE_TTL_MAX_MS;
    return (uint32_t)ms;
}

dns_cache_slot *dns_cache_find(dns_cache_slot *cache, int n, const char *name, uint64_t now_ms)
{
    for (int i = 0; i < n; i++) {
        if (cache[i].state != DNS_CACHE_EMPTY && dns_name_eq(cache[i].name, name)) {
            if (now_ms >= cache[i].expires_ms) { cache[i].state = DNS_CACHE_EMPTY; return 0; }
            return &cache[i];
        }
    }
    return 0;
}

dns_cache_slot *dns_cache_slot_for(dns_cache_slot *cache, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (cache[i].state != DNS_CACHE_EMPTY && dns_name_eq(cache[i].name, name))
            return &cache[i];                  /* refresh this name's existing entry */
    dns_cache_slot *victim = &cache[0];
    for (int i = 0; i < n; i++) {
        if (cache[i].state == DNS_CACHE_EMPTY) return &cache[i];
        if (cache[i].expires_ms < victim->expires_ms) victim = &cache[i];
    }
    return victim;                              /* full: evict the soonest-to-expire */
}

static void cache_set_name(dns_cache_slot *slot, const char *name)
{
    int i = 0;
    for (; name[i] && i < (int)sizeof(slot->name) - 1; i++) slot->name[i] = name[i];
    slot->name[i] = 0;
}

void dns_cache_put_positive(dns_cache_slot *slot, const char *name, uint32_t ip, uint32_t ttl_secs, uint64_t now_ms)
{
    if (ttl_secs == 0) return;                  /* RFC 1035: TTL 0 means "do not cache" */
    cache_set_name(slot, name);
    slot->ip = ip;
    slot->expires_ms = now_ms + dns_cache_clamp_ttl_ms(ttl_secs);
    slot->state = DNS_CACHE_POSITIVE;
}

void dns_cache_put_negative(dns_cache_slot *slot, const char *name, uint64_t now_ms)
{
    cache_set_name(slot, name);
    slot->expires_ms = now_ms + DNS_CACHE_NEG_TTL_MS;
    slot->state = DNS_CACHE_NEGATIVE;
}

/* ---- live query, cache-aware ---- */

static dns_cache_slot g_cache[DNS_CACHE_SIZE];

int dns_query(const char *name, uint16_t type, uint32_t *out_ip)
{
    if (type == DNS_A) {
        dns_cache_slot *hit = dns_cache_find(g_cache, DNS_CACHE_SIZE, name, net_now_ms());
        if (hit) {
            if (hit->state == DNS_CACHE_POSITIVE) {
                if (out_ip) *out_ip = hit->ip;
                kprintf("[dns] cache hit: %s -> %u.%u.%u.%u\n", name, OCTETS(hit->ip));
                return 0;
            }
            kprintf("[dns] cache hit (negative): %s\n", name);
            return -1;
        }
    }

    static int bound;
    if (!bound) {
        if (udp_bind(DNS_CLIENT_PORT, dns_handler) != 0)
            return -1;
        bound = 1;
    }

    uint8_t q[300];
    struct dns_hdr *h = (struct dns_hdr *)q;
    query_id = (uint16_t)(query_id + 0x9e37);     /* vary the id each call */
    if (query_id == 0) query_id = 0x1234;
    h->id      = htons(query_id);
    h->flags   = htons(0x0100);                   /* recursion desired */
    h->qdcount = htons(1);
    h->ancount = h->nscount = h->arcount = 0;

    int o = (int)sizeof(*h);
    int qn = encode_qname(q + o, name);
    if (qn < 0 || o + qn + 4 > (int)sizeof(q))
        return -1;
    o += qn;
    q[o++] = (uint8_t)(type >> 8); q[o++] = (uint8_t)type;   /* QTYPE  */
    q[o++] = 0;                    q[o++] = 1;                /* QCLASS = IN */

    resp_have = 0;

    /* Send; the gateway/DNS-server ARP may still be resolving, so retry while
     * pumping the RX path. */
    int sent = -1;
    uint64_t sdl = net_now_ms() + 2000;
    while (net_now_ms() < sdl) {
        sent = udp_send(IP_DNS, DNS_CLIENT_PORT, DNS_PORT, q, (unsigned)o);
        if (sent == 0)
            break;
        net_poll();
    }
    if (sent != 0)
        return -1;

    uint64_t dl = net_now_ms() + 3000;
    while (net_now_ms() < dl && !resp_have)
        net_poll();
    if (!resp_have)
        return -1;

    uint32_t ttl = 0;
    int rc = parse_response(type, out_ip, &ttl);
    if (type == DNS_A) {
        uint64_t now = net_now_ms();
        dns_cache_slot *slot = dns_cache_slot_for(g_cache, DNS_CACHE_SIZE, name);
        if (rc == 0) {
            dns_cache_put_positive(slot, name, *out_ip, ttl, now);
            kprintf("[dns] cached %s -> %u.%u.%u.%u (ttl=%us)\n", name, OCTETS(*out_ip), ttl);
        } else {
            dns_cache_put_negative(slot, name, now);
            kprintf("[dns] cached %s (negative, ttl=%us)\n", name, (unsigned)(DNS_CACHE_NEG_TTL_MS / 1000u));
        }
    }
    return rc;
}
