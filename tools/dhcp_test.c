/* Host-side DHCP client tests (net/dhcp.c): pure packet build/parse and lease-
 * timer logic, no NIC, no UDP, no QEMU -- the same separation as the rest of
 * net/dhcp.c between "pure" (host-testable) and "live transaction" (kernel-
 * only). Build/run: `make dhcp-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "dhcp.h"
#include "udp.h"
#include "netstack.h"
#include "inet.h"
#include "virtio_net.h"

/* Test doubles for the hardware-touching calls dhcp_configure()/dhcp_tick()/
 * send_renew() make. Nothing in this file calls those functions -- only the
 * pure build/parse/lease-timer functions are under test -- but net/dhcp.c is
 * one translation unit, so the linker still needs every symbol it references
 * resolved. net/netcfg.c (pure) is linked for real. */
int udp_bind(uint16_t port, udp_handler_t handler) { (void)port; (void)handler; return 0; }
int udp_send(uint32_t dst, uint16_t sp, uint16_t dp, const void *payload, size_t len)
{ (void)dst; (void)sp; (void)dp; (void)payload; (void)len; return -1; }
void net_poll(void) {}
uint64_t net_now_ms(void) { return 0; }
int virtio_net_present(void) { return 0; }
const uint8_t *virtio_net_mac(void) { static const uint8_t z[6]; return z; }
void kprintf(const char *fmt, ...) { (void)fmt; }

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

static const uint8_t MAC[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static const uint8_t OTHER_MAC[6] = { 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc };

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* Reads a big-endian uint32 at `p`. */
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* Find option `code`'s value pointer in a built packet's options area (mirrors
 * dhcp.c's internal find_option, reimplemented here so the test doesn't reach
 * into dhcp.c's static functions). */
static const uint8_t *find_opt(const uint8_t *pkt, int pktlen, uint8_t code, uint8_t *len_out)
{
    const uint8_t *opts = pkt + DHCP_FIXED_LEN + 4;
    int olen = pktlen - DHCP_FIXED_LEN - 4;
    int i = 0;
    while (i < olen) {
        uint8_t c = opts[i];
        if (c == 255) break;
        if (c == 0) { i++; continue; }
        if (i + 1 >= olen) break;
        uint8_t l = opts[i + 1];
        if (i + 2 + l > olen) break;
        if (c == code) { if (len_out) *len_out = l; return opts + i + 2; }
        i += 2 + l;
    }
    return 0;
}

/* Build a synthetic server reply (BOOTREPLY) by hand, options chosen by the
 * caller, for dhcp_parse_reply() to consume. Returns the length. */
static int build_reply(uint8_t *out, uint32_t xid, const uint8_t mac[6], uint32_t yiaddr,
                       int msgtype, int with_mask, int with_router, int with_dns,
                       int with_lease, int with_server_id, int two_dns)
{
    memset(out, 0, DHCP_FIXED_LEN);
    out[0] = 2;            /* op = BOOTREPLY */
    out[1] = 1;            /* htype = Ethernet */
    out[2] = 6;            /* hlen */
    uint32_t xn = xid;
    out[4] = (uint8_t)(xn >> 24); out[5] = (uint8_t)(xn >> 16);
    out[6] = (uint8_t)(xn >> 8);  out[7] = (uint8_t)xn;
    out[16] = (uint8_t)(yiaddr >> 24); out[17] = (uint8_t)(yiaddr >> 16);
    out[18] = (uint8_t)(yiaddr >> 8);  out[19] = (uint8_t)yiaddr;
    memcpy(out + 28, mac, 6);
    out[DHCP_FIXED_LEN + 0] = 0x63; out[DHCP_FIXED_LEN + 1] = 0x82;
    out[DHCP_FIXED_LEN + 2] = 0x53; out[DHCP_FIXED_LEN + 3] = 0x63;
    int o = DHCP_FIXED_LEN + 4;
    out[o++] = 53; out[o++] = 1; out[o++] = (uint8_t)msgtype;
    if (with_mask)   { out[o++] = 1;  out[o++] = 4; uint32_t v = IP4(255,255,255,0); out[o++]=(uint8_t)(v>>24); out[o++]=(uint8_t)(v>>16); out[o++]=(uint8_t)(v>>8); out[o++]=(uint8_t)v; }
    if (with_router) { out[o++] = 3;  out[o++] = 4; uint32_t v = IP4(10,0,2,2);      out[o++]=(uint8_t)(v>>24); out[o++]=(uint8_t)(v>>16); out[o++]=(uint8_t)(v>>8); out[o++]=(uint8_t)v; }
    if (with_dns) {
        uint8_t l = two_dns ? 8 : 4;
        out[o++] = 6; out[o++] = l;
        uint32_t v0 = IP4(10,0,2,3); out[o++]=(uint8_t)(v0>>24); out[o++]=(uint8_t)(v0>>16); out[o++]=(uint8_t)(v0>>8); out[o++]=(uint8_t)v0;
        if (two_dns) { uint32_t v1 = IP4(8,8,8,8); out[o++]=(uint8_t)(v1>>24); out[o++]=(uint8_t)(v1>>16); out[o++]=(uint8_t)(v1>>8); out[o++]=(uint8_t)v1; }
    }
    if (with_lease)  { out[o++] = 51; out[o++] = 4; uint32_t v = 7200; out[o++]=(uint8_t)(v>>24); out[o++]=(uint8_t)(v>>16); out[o++]=(uint8_t)(v>>8); out[o++]=(uint8_t)v; }
    if (with_server_id) { out[o++] = 54; out[o++] = 4; uint32_t v = IP4(10,0,2,2); out[o++]=(uint8_t)(v>>24); out[o++]=(uint8_t)(v>>16); out[o++]=(uint8_t)(v>>8); out[o++]=(uint8_t)v; }
    out[o++] = 255;
    return o;
}

int main(void)
{
    uint8_t pkt[400];

    /* --- dhcp_build_discover --- */
    {
        int n = dhcp_build_discover(pkt, sizeof pkt, 0x12345678u, MAC);
        check_ok("DISCOVER builds", n > 0);
        check_ok("DISCOVER op=BOOTREQUEST(1)", pkt[0] == 1);
        check_ok("DISCOVER htype=1 hlen=6", pkt[1] == 1 && pkt[2] == 6);
        check_ok("DISCOVER xid echoed", be32(pkt + 4) == 0x12345678u);
        check_ok("DISCOVER broadcast flag set", (pkt[10] & 0x80) != 0);
        check_ok("DISCOVER ciaddr is 0.0.0.0", be32(pkt + 12) == 0);
        check_ok("DISCOVER chaddr == our MAC", memcmp(pkt + 28, MAC, 6) == 0);
        check_ok("DISCOVER magic cookie", pkt[DHCP_FIXED_LEN] == 0x63 && pkt[DHCP_FIXED_LEN+1] == 0x82 &&
                  pkt[DHCP_FIXED_LEN+2] == 0x53 && pkt[DHCP_FIXED_LEN+3] == 0x63);
        uint8_t l; const uint8_t *p = find_opt(pkt, n, 53, &l);
        check_ok("DISCOVER msg type option = DISCOVER(1)", p && l == 1 && p[0] == DHCP_DISCOVER);
        check_ok("DISCOVER has no requested-IP option (none offered yet)", find_opt(pkt, n, 50, &l) == 0);
        check_ok("DISCOVER too-small buffer rejected", dhcp_build_discover(pkt, 32, 1, MAC) == -1);
    }

    /* --- dhcp_build_request: SELECTING (ciaddr=0) --- */
    {
        int n = dhcp_build_request(pkt, sizeof pkt, 0xAAu, MAC, 0,
                                   IP4(10,0,2,15), IP4(10,0,2,2), 1);
        check_ok("REQUEST(selecting) builds", n > 0);
        check_ok("REQUEST(selecting) ciaddr is 0.0.0.0", be32(pkt + 12) == 0);
        check_ok("REQUEST(selecting) broadcast flag set", (pkt[10] & 0x80) != 0);
        uint8_t l; const uint8_t *p = find_opt(pkt, n, 53, &l);
        check_ok("REQUEST(selecting) msg type = REQUEST(3)", p && p[0] == DHCP_REQUEST);
        p = find_opt(pkt, n, 50, &l);
        check_ok("REQUEST(selecting) requested-IP option present and correct", p && l == 4 && be32(p) == IP4(10,0,2,15));
        p = find_opt(pkt, n, 54, &l);
        check_ok("REQUEST(selecting) server-id option present and correct", p && l == 4 && be32(p) == IP4(10,0,2,2));
    }

    /* --- dhcp_build_request: RENEWING (ciaddr != 0) --- */
    {
        int n = dhcp_build_request(pkt, sizeof pkt, 0xBBu, MAC, IP4(10,0,2,15),
                                   0 /* unused */, 0 /* unused */, 0 /* unicast */);
        check_ok("REQUEST(renewing) builds", n > 0);
        check_ok("REQUEST(renewing) ciaddr states the held lease", be32(pkt + 12) == IP4(10,0,2,15));
        check_ok("REQUEST(renewing) broadcast flag clear (unicast renewal)", (pkt[10] & 0x80) == 0);
        check_ok("REQUEST(renewing) omits requested-IP option (ciaddr suffices)", find_opt(pkt, n, 50, 0) == 0);
        check_ok("REQUEST(renewing) omits server-id option", find_opt(pkt, n, 54, 0) == 0);
    }

    /* --- dhcp_parse_reply: a full OFFER/ACK --- */
    {
        uint8_t reply[400];
        int rn = build_reply(reply, 0x999u, MAC, IP4(10,0,2,15), DHCP_OFFER, 1, 1, 1, 1, 1, 0);
        struct dhcp_lease lease;
        int t = dhcp_parse_reply(reply, rn, 0x999u, MAC, &lease);
        check_ok("OFFER parses as DHCP_OFFER", t == DHCP_OFFER);
        check_ok("OFFER yiaddr", lease.yiaddr == IP4(10,0,2,15));
        check_ok("OFFER mask", lease.mask == IP4(255,255,255,0));
        check_ok("OFFER router", lease.router == IP4(10,0,2,2));
        check_ok("OFFER dns[0]", lease.dns[0] == IP4(10,0,2,3));
        check_ok("OFFER dns[1] absent -> 0", lease.dns[1] == 0);
        check_ok("OFFER lease_secs", lease.lease_secs == 7200);
        check_ok("OFFER server_id", lease.server_id == IP4(10,0,2,2));

        rn = build_reply(reply, 0x999u, MAC, IP4(10,0,2,15), DHCP_OFFER, 1, 1, 1, 0, 1, 1);
        t = dhcp_parse_reply(reply, rn, 0x999u, MAC, &lease);
        check_ok("two-DNS reply: dns[0]", lease.dns[0] == IP4(10,0,2,3));
        check_ok("two-DNS reply: dns[1]", lease.dns[1] == IP4(8,8,8,8));
        check_ok("no-lease-option reply: lease_secs left 0", lease.lease_secs == 0);
    }

    /* --- dhcp_parse_reply: rejection paths --- */
    {
        uint8_t reply[400];
        struct dhcp_lease lease;
        int rn = build_reply(reply, 0x999u, MAC, IP4(10,0,2,15), DHCP_OFFER, 1, 1, 1, 1, 1, 0);

        check_ok("wrong xid -> rejected", dhcp_parse_reply(reply, rn, 0x998u, MAC, &lease) == -1);
        check_ok("wrong chaddr -> rejected", dhcp_parse_reply(reply, rn, 0x999u, OTHER_MAC, &lease) == -1);

        uint8_t bad_op[400]; memcpy(bad_op, reply, (size_t)rn); bad_op[0] = 1;  /* BOOTREQUEST, not REPLY */
        check_ok("op != BOOTREPLY -> rejected", dhcp_parse_reply(bad_op, rn, 0x999u, MAC, &lease) == -1);

        uint8_t bad_cookie[400]; memcpy(bad_cookie, reply, (size_t)rn); bad_cookie[DHCP_FIXED_LEN] ^= 0xff;
        check_ok("bad magic cookie -> rejected", dhcp_parse_reply(bad_cookie, rn, 0x999u, MAC, &lease) == -1);

        check_ok("truncated packet -> rejected", dhcp_parse_reply(reply, DHCP_FIXED_LEN, 0x999u, MAC, &lease) == -1);

        /* a reply with no message-type option at all */
        uint8_t no_type[400]; memset(no_type, 0, DHCP_FIXED_LEN);
        no_type[0] = 2; no_type[1] = 1; no_type[2] = 6;
        memcpy(no_type + 28, MAC, 6);
        no_type[DHCP_FIXED_LEN+0]=0x63; no_type[DHCP_FIXED_LEN+1]=0x82; no_type[DHCP_FIXED_LEN+2]=0x53; no_type[DHCP_FIXED_LEN+3]=0x63;
        no_type[DHCP_FIXED_LEN+4] = 255;
        check_ok("missing msg-type option -> rejected", dhcp_parse_reply(no_type, DHCP_FIXED_LEN + 5, 0x999u, MAC, &lease) == -1);

        rn = build_reply(reply, 0x999u, MAC, IP4(10,0,2,15), DHCP_NAK, 0, 0, 0, 0, 0, 0);
        check_ok("NAK parses as DHCP_NAK", dhcp_parse_reply(reply, rn, 0x999u, MAC, &lease) == DHCP_NAK);
    }

    /* --- dhcp_lease_due: T1/T2/expiry thresholds --- */
    {
        uint64_t obtained = 1000000ull;       /* arbitrary ms epoch */
        uint32_t lease = 1000;                 /* 1000 s lease -> T1=500s, T2=875s */
        check_ok("due: well before T1 -> NONE",  dhcp_lease_due(obtained, lease, obtained) == DHCP_DUE_NONE);
        check_ok("due: just before T1 -> NONE",  dhcp_lease_due(obtained, lease, obtained + 499000) == DHCP_DUE_NONE);
        check_ok("due: at T1 -> RENEW",          dhcp_lease_due(obtained, lease, obtained + 500000) == DHCP_DUE_RENEW);
        check_ok("due: between T1/T2 -> RENEW",  dhcp_lease_due(obtained, lease, obtained + 600000) == DHCP_DUE_RENEW);
        check_ok("due: at T2 -> REBIND",         dhcp_lease_due(obtained, lease, obtained + 875000) == DHCP_DUE_REBIND);
        check_ok("due: between T2/expiry -> REBIND", dhcp_lease_due(obtained, lease, obtained + 999000) == DHCP_DUE_REBIND);
        check_ok("due: at expiry -> EXPIRED",    dhcp_lease_due(obtained, lease, obtained + 1000000) == DHCP_DUE_EXPIRED);
        check_ok("due: long past expiry -> EXPIRED", dhcp_lease_due(obtained, lease, obtained + 5000000) == DHCP_DUE_EXPIRED);
        check_ok("due: lease_secs=0 -> NONE (no lease tracked)", dhcp_lease_due(obtained, 0, obtained + 999999999ull) == DHCP_DUE_NONE);
    }

    printf(failures ? "\nDHCP TEST: %d FAILURE(S)\n" : "\nDHCP TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
