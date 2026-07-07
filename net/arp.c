/* ARP cache + request/reply state machine — see arp.h. */
#include "arp.h"
#include "eth.h"
#include "inet.h"
#include "virtio_net.h"
#include "string.h"
#include "kio.h"

/* ARP packet for IPv4-over-Ethernet (RFC 826). All multi-byte fields are on the
 * wire in network order. */
struct arp_pkt {
    uint16_t htype;     /* 1 = Ethernet            */
    uint16_t ptype;     /* 0x0800 = IPv4           */
    uint8_t  hlen;      /* 6                       */
    uint8_t  plen;      /* 4                       */
    uint16_t oper;      /* 1 = request, 2 = reply  */
    uint8_t  sha[6];    /* sender MAC              */
    uint32_t spa;       /* sender IP (network ord) */
    uint8_t  tha[6];    /* target MAC              */
    uint32_t tpa;       /* target IP (network ord) */
} __attribute__((packed));

#define ARP_HTYPE_ETH   1
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2

static arp_entry_t cache[ARP_CACHE_SIZE];

void arp_init(void)
{
    memset(cache, 0, sizeof(cache));
}

/* Find an entry for `ip`, demoting it to EMPTY if its TTL has passed. */
static arp_entry_t *find(uint32_t ip)
{
    uint64_t now = net_now_ms();
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].state != ARP_EMPTY && cache[i].ip == ip) {
            if (cache[i].state == ARP_RESOLVED && now >= cache[i].expires)
                cache[i].state = ARP_EMPTY;     /* lazy expiry */
            return &cache[i];
        }
    }
    return NULL;
}

/* Pick a slot for a new entry: a free one, else evict the soonest-to-expire. */
static arp_entry_t *alloc_slot(void)
{
    arp_entry_t *victim = &cache[0];
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].state == ARP_EMPTY)
            return &cache[i];
        if (cache[i].expires < victim->expires)
            victim = &cache[i];
    }
    return victim;                               /* cache full: reuse the oldest */
}

/* Insert or refresh a resolved (ip -> mac) binding. */
static void learn(uint32_t ip, const uint8_t mac[6])
{
    arp_entry_t *e = find(ip);
    if (!e)
        e = alloc_slot();
    e->ip = ip;
    memcpy(e->mac, mac, 6);
    e->state   = ARP_RESOLVED;
    e->expires = net_now_ms() + ARP_TTL_MS;
}

void arp_request(uint32_t ip)
{
    struct arp_pkt p;
    memset(&p, 0, sizeof(p));
    p.htype = htons(ARP_HTYPE_ETH);
    p.ptype = htons(ETH_P_IPV4);
    p.hlen  = 6;
    p.plen  = 4;
    p.oper  = htons(ARP_OP_REQUEST);
    memcpy(p.sha, virtio_net_mac(), 6);
    p.spa = htonl(IP_LOCAL);
    /* tha left zero (unknown) */
    p.tpa = htonl(ip);
    eth_send(eth_broadcast, ETH_P_ARP, &p, sizeof(p));
}

int arp_lookup(uint32_t ip, uint8_t mac_out[6])
{
    arp_entry_t *e = find(ip);
    if (e && e->state == ARP_RESOLVED) {
        if (mac_out) memcpy(mac_out, e->mac, 6);
        return 1;
    }
    return 0;
}

int arp_resolve(uint32_t ip, uint8_t mac_out[6])
{
    arp_entry_t *e = find(ip);
    if (e && e->state == ARP_RESOLVED) {
        if (mac_out) memcpy(mac_out, e->mac, 6);
        return 1;
    }
    /* Not known: create/refresh a PENDING entry and (re)send a request. We
     * re-ask if a pending request is older than ~1 s (its retry deadline). */
    uint64_t now = net_now_ms();
    if (!e)
        e = alloc_slot();
    if (e->state != ARP_PENDING || now >= e->expires) {
        e->ip      = ip;
        e->state   = ARP_PENDING;
        e->expires = now + 1000;                 /* retry after 1 s */
        arp_request(ip);
    }
    return 0;
}

void arp_input(const void *payload, size_t len)
{
    if (len < sizeof(struct arp_pkt))
        return;
    const struct arp_pkt *p = (const struct arp_pkt *)payload;

    if (ntohs(p->htype) != ARP_HTYPE_ETH || ntohs(p->ptype) != ETH_P_IPV4 ||
        p->hlen != 6 || p->plen != 4)
        return;                                  /* not IPv4-over-Ethernet */

    uint32_t spa = ntohl(p->spa);
    uint32_t tpa = ntohl(p->tpa);
    uint16_t op  = ntohs(p->oper);

    /* Learn the sender from any ARP we see (request or reply). */
    if (spa)
        learn(spa, p->sha);

    /* Answer requests addressed to our IP. */
    if (op == ARP_OP_REQUEST && tpa == IP_LOCAL) {
        struct arp_pkt r;
        memset(&r, 0, sizeof(r));
        r.htype = htons(ARP_HTYPE_ETH);
        r.ptype = htons(ETH_P_IPV4);
        r.hlen  = 6;
        r.plen  = 4;
        r.oper  = htons(ARP_OP_REPLY);
        memcpy(r.sha, virtio_net_mac(), 6);
        r.spa = htonl(IP_LOCAL);
        memcpy(r.tha, p->sha, 6);
        r.tpa = htonl(spa);
        eth_send(p->sha, ETH_P_ARP, &r, sizeof(r));
    }
}

int arp_cache_count(void)
{
    uint64_t now = net_now_ms();
    int n = 0;
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (cache[i].state == ARP_RESOLVED && now < cache[i].expires)
            n++;
    return n;
}

void arp_test_expire_all(void)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (cache[i].state == ARP_RESOLVED)
            cache[i].expires = 0;                /* now >= 0 -> expired on next find() */
}
