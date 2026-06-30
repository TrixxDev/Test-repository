/* DHCP client — see dhcp.h. */
#include "dhcp.h"
#include "udp.h"
#include "netcfg.h"
#include "netstack.h"
#include "inet.h"
#include "virtio_net.h"
#include "string.h"
#include "kio.h"

#define OPT_PAD            0
#define OPT_SUBNET_MASK    1
#define OPT_ROUTER         3
#define OPT_DNS            6
#define OPT_REQUESTED_IP   50
#define OPT_LEASE_TIME     51
#define OPT_MSG_TYPE       53
#define OPT_SERVER_ID      54
#define OPT_PARAM_REQ_LIST 55
#define OPT_END            255

#define DHCP_OP_REQUEST  1
#define DHCP_OP_REPLY    2
#define DHCP_HTYPE_ETH   1

/* Fixed header + magic cookie + generous room for the handful of options we
 * ever send (the longest, a SELECTING REQUEST, is ~26 bytes of options). */
#define DHCP_PKT_MIN (DHCP_FIXED_LEN + 4 + 64)

struct dhcp_hdr {
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
} __attribute__((packed));

#define OCTETS(ip) (unsigned)(((ip) >> 24) & 0xff), (unsigned)(((ip) >> 16) & 0xff), \
                   (unsigned)(((ip) >> 8) & 0xff),  (unsigned)((ip) & 0xff)

/* ---- pure packet build/parse (host-testable) ---- */

static int put_hdr(uint8_t *out, size_t cap, uint32_t xid, const uint8_t mac[6],
                   uint32_t ciaddr, int broadcast)
{
    if (cap < DHCP_PKT_MIN) return -1;
    struct dhcp_hdr *h = (struct dhcp_hdr *)out;
    memset(out, 0, DHCP_FIXED_LEN);
    h->op     = DHCP_OP_REQUEST;
    h->htype  = DHCP_HTYPE_ETH;
    h->hlen   = 6;
    h->xid    = htonl(xid);
    h->flags  = broadcast ? htons(0x8000) : 0;
    h->ciaddr = htonl(ciaddr);
    memcpy(h->chaddr, mac, 6);
    out[DHCP_FIXED_LEN + 0] = 0x63; out[DHCP_FIXED_LEN + 1] = 0x82;
    out[DHCP_FIXED_LEN + 2] = 0x53; out[DHCP_FIXED_LEN + 3] = 0x63;
    return DHCP_FIXED_LEN + 4;
}

static int put_ip_opt(uint8_t *out, int o, uint8_t code, uint32_t ip)
{
    out[o++] = code; out[o++] = 4;
    out[o++] = (uint8_t)(ip >> 24); out[o++] = (uint8_t)(ip >> 16);
    out[o++] = (uint8_t)(ip >> 8);  out[o++] = (uint8_t)ip;
    return o;
}

int dhcp_build_discover(uint8_t *out, size_t cap, uint32_t xid, const uint8_t mac[6])
{
    int o = put_hdr(out, cap, xid, mac, 0, 1);
    if (o < 0) return -1;
    out[o++] = OPT_MSG_TYPE; out[o++] = 1; out[o++] = DHCP_DISCOVER;
    out[o++] = OPT_PARAM_REQ_LIST; out[o++] = 3;
    out[o++] = OPT_SUBNET_MASK; out[o++] = OPT_ROUTER; out[o++] = OPT_DNS;
    out[o++] = OPT_END;
    return o;
}

int dhcp_build_request(uint8_t *out, size_t cap, uint32_t xid, const uint8_t mac[6],
                       uint32_t ciaddr, uint32_t requested_ip, uint32_t server_id,
                       int broadcast)
{
    int o = put_hdr(out, cap, xid, mac, ciaddr, broadcast);
    if (o < 0) return -1;
    out[o++] = OPT_MSG_TYPE; out[o++] = 1; out[o++] = DHCP_REQUEST;
    if (ciaddr == 0) {                          /* SELECTING: state the offer explicitly */
        o = put_ip_opt(out, o, OPT_REQUESTED_IP, requested_ip);
        o = put_ip_opt(out, o, OPT_SERVER_ID, server_id);
    }
    out[o++] = OPT_PARAM_REQ_LIST; out[o++] = 3;
    out[o++] = OPT_SUBNET_MASK; out[o++] = OPT_ROUTER; out[o++] = OPT_DNS;
    out[o++] = OPT_END;
    return o;
}

/* Find option `code` in the TLV options area; fills *len_out and returns a
 * pointer to its value, or NULL if absent/malformed. */
static const uint8_t *find_option(const uint8_t *opts, size_t olen, uint8_t code, uint8_t *len_out)
{
    size_t i = 0;
    while (i < olen) {
        uint8_t c = opts[i];
        if (c == OPT_END) break;
        if (c == OPT_PAD) { i++; continue; }
        if (i + 1 >= olen) break;
        uint8_t l = opts[i + 1];
        if (i + 2 + l > olen) break;
        if (c == code) { if (len_out) *len_out = l; return opts + i + 2; }
        i += 2u + l;
    }
    return 0;
}

static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

int dhcp_parse_reply(const uint8_t *buf, size_t len, uint32_t xid, const uint8_t mac[6],
                     struct dhcp_lease *out)
{
    memset(out, 0, sizeof(*out));
    if (len < DHCP_FIXED_LEN + 4) return -1;
    const struct dhcp_hdr *h = (const struct dhcp_hdr *)buf;
    if (h->op != DHCP_OP_REPLY) return -1;
    if (ntohl(h->xid) != xid) return -1;
    if (memcmp(h->chaddr, mac, 6) != 0) return -1;

    const uint8_t *cookie = buf + DHCP_FIXED_LEN;
    if (cookie[0] != 0x63 || cookie[1] != 0x82 || cookie[2] != 0x53 || cookie[3] != 0x63)
        return -1;

    const uint8_t *opts = buf + DHCP_FIXED_LEN + 4;
    size_t olen = len - DHCP_FIXED_LEN - 4;

    uint8_t l;
    const uint8_t *p = find_option(opts, olen, OPT_MSG_TYPE, &l);
    if (!p || l < 1) return -1;
    int msgtype = p[0];

    out->yiaddr = ntohl(h->yiaddr);

    if ((p = find_option(opts, olen, OPT_SUBNET_MASK, &l)) && l == 4) out->mask = be32(p);
    if ((p = find_option(opts, olen, OPT_ROUTER, &l))      && l >= 4) out->router = be32(p);
    if ((p = find_option(opts, olen, OPT_DNS, &l))         && l >= 4) {
        out->dns[0] = be32(p);
        if (l >= 8) out->dns[1] = be32(p + 4);
    }
    if ((p = find_option(opts, olen, OPT_LEASE_TIME, &l))  && l == 4) out->lease_secs = be32(p);
    if ((p = find_option(opts, olen, OPT_SERVER_ID, &l))   && l == 4) out->server_id = be32(p);

    return msgtype;
}

enum dhcp_due dhcp_lease_due(uint64_t obtained_ms, uint32_t lease_secs, uint64_t now_ms)
{
    if (lease_secs == 0) return DHCP_DUE_NONE;          /* no lease being tracked */
    uint64_t lease_ms = (uint64_t)lease_secs * 1000u;
    uint64_t t1     = obtained_ms + lease_ms / 2;        /* RFC 2131: 0.5 * lease   */
    uint64_t t2     = obtained_ms + (lease_ms * 7) / 8;  /* RFC 2131: 0.875 * lease */
    uint64_t expiry = obtained_ms + lease_ms;
    if (now_ms >= expiry) return DHCP_DUE_EXPIRED;
    if (now_ms >= t2)     return DHCP_DUE_REBIND;
    if (now_ms >= t1)     return DHCP_DUE_RENEW;
    return DHCP_DUE_NONE;
}

/* ---- live transaction (I/O, kernel-side only) ---- */

static volatile int      resp_have;
static volatile unsigned resp_len;
static uint8_t           resp_buf[600];
static uint32_t          g_xid;
static int               g_active;          /* 1 once a lease is installed */
static uint64_t          g_obtained_ms;
static uint32_t          g_lease_secs;
static uint32_t          g_server_id;
static int               g_renewed_t1, g_rebound_t2;   /* one attempt per lease window */

static void dhcp_handler(uint32_t src, uint16_t sport, const void *data, size_t len)
{
    (void)src; (void)sport;
    unsigned n = (unsigned)len < sizeof(resp_buf) ? (unsigned)len : sizeof(resp_buf);
    memcpy(resp_buf, data, n);
    resp_len  = n;
    resp_have = 1;
}

void dhcp_init(void)
{
    resp_have = 0; g_active = 0;
    g_xid = 0; g_obtained_ms = 0; g_lease_secs = 0; g_server_id = 0;
    g_renewed_t1 = 0; g_rebound_t2 = 0;
    udp_bind(DHCP_CLIENT_PORT, dhcp_handler);
}

int dhcp_configure(unsigned timeout_ms)
{
    if (!virtio_net_present()) return -1;

    uint8_t pkt[DHCP_PKT_MIN];
    const uint8_t *mac = virtio_net_mac();
    g_xid = (uint32_t)net_now_ms() ^ ((uint32_t)mac[2] << 24 | (uint32_t)mac[3] << 16 |
                                       (uint32_t)mac[4] << 8 | mac[5]);
    if (g_xid == 0) g_xid = 0xA5A5A5A5u;

    uint64_t deadline = net_now_ms() + timeout_ms;

    int plen = dhcp_build_discover(pkt, sizeof(pkt), g_xid, mac);
    if (plen < 0) return -1;
    kprintf("[dhcp] DISCOVER (xid=%x)\n", g_xid);
    resp_have = 0;
    int sent = -1;
    while (net_now_ms() < deadline) {
        sent = udp_send(IP_BROADCAST, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, pkt, (unsigned)plen);
        if (sent == 0) break;
        net_poll();
    }
    if (sent != 0) { kprintf("[dhcp] DISCOVER: send failed (no link?)\n"); return -1; }

    struct dhcp_lease offer;
    int msgtype = -1;
    while (net_now_ms() < deadline) {
        net_poll();
        if (resp_have) {
            resp_have = 0;
            int t = dhcp_parse_reply(resp_buf, resp_len, g_xid, mac, &offer);
            if (t == DHCP_OFFER) { msgtype = t; break; }
        }
    }
    if (msgtype != DHCP_OFFER) { kprintf("[dhcp] no OFFER (timeout) -- staying on static config\n"); return -1; }
    kprintf("[dhcp] OFFER %u.%u.%u.%u from server %u.%u.%u.%u\n",
            OCTETS(offer.yiaddr), OCTETS(offer.server_id));

    plen = dhcp_build_request(pkt, sizeof(pkt), g_xid, mac, 0, offer.yiaddr, offer.server_id, 1);
    if (plen < 0) return -1;
    resp_have = 0;
    sent = -1;
    while (net_now_ms() < deadline) {
        sent = udp_send(IP_BROADCAST, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, pkt, (unsigned)plen);
        if (sent == 0) break;
        net_poll();
    }
    if (sent != 0) { kprintf("[dhcp] REQUEST: send failed\n"); return -1; }

    struct dhcp_lease ack;
    msgtype = -1;
    while (net_now_ms() < deadline) {
        net_poll();
        if (resp_have) {
            resp_have = 0;
            int t = dhcp_parse_reply(resp_buf, resp_len, g_xid, mac, &ack);
            if (t == DHCP_ACK || t == DHCP_NAK) { msgtype = t; break; }
        }
    }
    if (msgtype == DHCP_NAK)  { kprintf("[dhcp] NAK -- offer withdrawn, staying on static config\n"); return -1; }
    if (msgtype != DHCP_ACK)  { kprintf("[dhcp] no ACK (timeout) -- staying on static config\n"); return -1; }

    uint32_t mask  = ack.mask  ? ack.mask  : IP4(255, 255, 255, 0);
    uint32_t lease = ack.lease_secs ? ack.lease_secs : 86400u;  /* sane default if the server omits it */

    netcfg_set(ack.yiaddr, mask, ack.router, ack.dns[0], ack.dns[1]);
    g_server_id   = ack.server_id ? ack.server_id : offer.server_id;
    g_obtained_ms = net_now_ms();
    g_lease_secs  = lease;
    g_renewed_t1  = 0;
    g_rebound_t2  = 0;
    g_active      = 1;

    kprintf("[dhcp] ACK: bound %u.%u.%u.%u mask %u.%u.%u.%u gw %u.%u.%u.%u dns %u.%u.%u.%u lease=%us\n",
            OCTETS(ack.yiaddr), OCTETS(mask), OCTETS(ack.router), OCTETS(ack.dns[0]), lease);
    return 0;
}

/* One-shot (non-blocking) renewal send: a fresh xid, ciaddr = our current
 * lease (RENEWING/REBINDING per RFC 2131 §4.3.6 -- no options 50/54). The
 * matching ACK/NAK, if any, is picked up by dhcp_tick() on a later call. */
static void send_renew(uint32_t dst, int broadcast)
{
    uint8_t pkt[DHCP_PKT_MIN];
    const uint8_t *mac = virtio_net_mac();
    g_xid += 1;
    int plen = dhcp_build_request(pkt, sizeof(pkt), g_xid, mac, g_net_config.ip, 0, 0, broadcast);
    if (plen < 0) return;
    resp_have = 0;
    udp_send(dst, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, pkt, (unsigned)plen);
    kprintf("[dhcp] renewing (xid=%x) -> %u.%u.%u.%u\n", g_xid, OCTETS(dst));
}

void dhcp_tick(void)
{
    if (!g_active) return;
    uint64_t now = net_now_ms();

    /* A renewal reply, if one is waiting. dhcp_tick() runs INSIDE net_poll(),
     * so it must never call net_poll() itself -- this is opportunistic, not a
     * blocking wait. */
    if (resp_have) {
        resp_have = 0;
        struct dhcp_lease ack;
        int t = dhcp_parse_reply(resp_buf, resp_len, g_xid, virtio_net_mac(), &ack);
        if (t == DHCP_ACK) {
            uint32_t mask  = ack.mask        ? ack.mask        : g_net_config.mask;
            uint32_t gw    = ack.router      ? ack.router      : g_net_config.gateway;
            uint32_t dns0  = ack.dns[0]      ? ack.dns[0]      : g_net_config.dns[0];
            uint32_t lease = ack.lease_secs  ? ack.lease_secs  : g_lease_secs;
            netcfg_set(ack.yiaddr, mask, gw, dns0, ack.dns[1]);
            if (ack.server_id) g_server_id = ack.server_id;
            g_obtained_ms = now; g_lease_secs = lease;
            g_renewed_t1 = 0; g_rebound_t2 = 0;      /* fresh window */
            kprintf("[dhcp] renewed: lease=%us\n", lease);
        } else if (t == DHCP_NAK) {
            kprintf("[dhcp] renewal NAK -- falling back to static config\n");
            netcfg_reset_static();
            g_active = 0;
            return;
        }
        /* anything else (stale/unmatched reply): ignore, lease keeps running */
    }

    enum dhcp_due due = dhcp_lease_due(g_obtained_ms, g_lease_secs, now);
    if (due == DHCP_DUE_EXPIRED) {
        kprintf("[dhcp] lease expired without renewal -- falling back to static config\n");
        netcfg_reset_static();
        g_active = 0;
    } else if (due == DHCP_DUE_REBIND && !g_rebound_t2) {
        g_rebound_t2 = 1;
        send_renew(IP_BROADCAST, 1);
    } else if (due == DHCP_DUE_RENEW && !g_renewed_t1) {
        g_renewed_t1 = 1;
        send_renew(g_server_id, 0);
    }
}
