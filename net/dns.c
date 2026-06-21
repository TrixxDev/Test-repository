/* DNS resolver over UDP — see dns.h. */
#include "dns.h"
#include "udp.h"
#include "netstack.h"
#include "inet.h"
#include "string.h"

#define IP_DNS          IP4(10, 0, 2, 3)    /* SLIRP virtual DNS server */
#define DNS_PORT        53
#define DNS_CLIENT_PORT 50053               /* our ephemeral source port */

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

static int parse_response(uint16_t type, uint32_t *out_ip)
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
        uint16_t rdlen = (uint16_t)((p[8] << 8) | p[9]);
        p += 10;
        if (p + rdlen > end)
            break;
        if (atype == DNS_A && rdlen == 4 && (type == DNS_A)) {
            if (out_ip)
                *out_ip = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                          ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
            return 0;
        }
        p += rdlen;
    }
    return -1;                           /* no matching record */
}

int dns_query(const char *name, uint16_t type, uint32_t *out_ip)
{
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

    return parse_response(type, out_ip);
}
