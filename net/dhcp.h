/* DHCP client (RFC 2131 / RFC 2132) — Phase 15.3.
 *
 * Brings g_net_config (net/netcfg.h) up from a real lease instead of the
 * compile-time SLIRP defaults: DISCOVER -> OFFER -> REQUEST -> ACK, then T1/T2
 * renewal for as long as the lease lives, falling back to the static defaults
 * on timeout, NAK, or lease loss. The rest of the stack never sees a half-
 * configured network -- net_init() seeds the static config first, and
 * dhcp_configure() only ever overwrites it on a verified ACK. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* DHCP message types (option 53, RFC 2132 §9.6). */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/* BOOTP/DHCP fixed header length before options (RFC 2131 fig. 1), and the
 * magic cookie that opens the options area (RFC 2132 §2). */
#define DHCP_FIXED_LEN    236
#define DHCP_MAGIC_COOKIE 0x63825363u

void dhcp_init(void);

/* Run a full DISCOVER -> OFFER -> REQUEST -> ACK transaction, blocking
 * (bounded by `timeout_ms` total) and pumping net_poll() while it waits. On
 * success, installs the lease into g_net_config and returns 0. On any failure
 * (no NIC, no OFFER, NAK, timeout), g_net_config is left exactly as it was
 * (netcfg_init()'s static defaults, or whatever the caller set) and this
 * returns -1. */
int dhcp_configure(unsigned timeout_ms);

/* Called from net_poll(): cheap (one clock comparison) unless a renewal
 * deadline (T1/T2) has actually passed, and a no-op until dhcp_configure()
 * has installed a lease. Never blocks and never calls net_poll() itself --
 * renewal is asynchronous, resolved opportunistically across later ticks. */
void dhcp_tick(void);

/* --- pure, host-testable packet build/parse (no I/O, no globals) --- */

/* A decoded lease: yiaddr plus whichever options the server included (0 if a
 * given option was absent -- the caller decides on defaults). */
struct dhcp_lease {
    uint32_t yiaddr;
    uint32_t server_id;     /* option 54 */
    uint32_t mask;          /* option 1  */
    uint32_t router;        /* option 3 (first router) */
    uint32_t dns[2];        /* option 6 (first two servers) */
    uint32_t lease_secs;    /* option 51 */
};

/* Build a DISCOVER into `out` (capacity `cap`). Returns the byte length, or
 * -1 if `cap` is too small. */
int dhcp_build_discover(uint8_t *out, size_t cap, uint32_t xid, const uint8_t mac[6]);

/* Build a REQUEST. `ciaddr` selects the RFC 2131 state: 0 means SELECTING
 * (right after an OFFER -- `requested_ip`/`server_id` are sent as options
 * 50/54); nonzero means RENEWING/REBINDING (a lease already held -- ciaddr
 * states it directly, options 50/54 are omitted per §4.3.6, and
 * `requested_ip`/`server_id` are ignored). `broadcast` sets the BOOTP
 * broadcast flag. Returns the byte length, or -1 if `cap` is too small. */
int dhcp_build_request(uint8_t *out, size_t cap, uint32_t xid, const uint8_t mac[6],
                       uint32_t ciaddr, uint32_t requested_ip, uint32_t server_id,
                       int broadcast);

/* Parse a server reply addressed to `xid`/`mac`. Returns the DHCP message
 * type (DHCP_OFFER/DHCP_ACK/DHCP_NAK/...) with `out` filled from whichever
 * options were present (absent ones left 0), or -1 if the packet isn't a
 * well-formed reply to our transaction (wrong op/xid/chaddr, bad magic
 * cookie, truncated, or missing option 53). */
int dhcp_parse_reply(const uint8_t *buf, size_t len, uint32_t xid, const uint8_t mac[6],
                     struct dhcp_lease *out);

/* Lease-timer thresholds as a pure function of wall time -- host-testable
 * without waiting out a real lease (the same idea as arp_test_expire_all()).
 * T1/T2 use RFC 2131's suggested defaults (0.5 / 0.875 of the lease). */
enum dhcp_due { DHCP_DUE_NONE, DHCP_DUE_RENEW, DHCP_DUE_REBIND, DHCP_DUE_EXPIRED };
enum dhcp_due dhcp_lease_due(uint64_t obtained_ms, uint32_t lease_secs, uint64_t now_ms);
