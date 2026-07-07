/* Network stack entry points (kernel side).
 *
 * Layering: virtio_net (transport) -> eth (framing/dispatch) -> arp / ipv4 ...
 * net_poll() pumps received frames up through eth_input(); for now it is driven
 * from active waits (the ARP self-test, later a net thread/daemon). */
#pragma once

void net_init(void);        /* initialise the protocol layers (ARP cache, ...) */
void net_poll(void);        /* drain the RX ring into eth_input() */
void net_selftest(void);    /* Phase 4/5 proof: Ethernet + ARP scenarios */

/* DHCP (net/dhcp.h, Phase 15.3): replace the static net config with a real
 * lease. Blocks up to `timeout_ms`; on failure the static config (already
 * live from net_init()) is untouched. Best called once, right after
 * net_init(), before anything else touches the network. */
int  dhcp_configure(unsigned timeout_ms);

/* Synchronous HTTP/1.0 GET of `path` from `host`:80 (DNS -> TCP -> GET -> close).
 * Writes up to `cap` response bytes (status line + headers + body) into `buf`.
 * Returns bytes received (>=0), or negative on error: -1 no NIC/args, -2 DNS
 * failed, -3 connect failed. Blocks (bounded); the caller must run with
 * interrupts enabled so the PIT clock advances. */
int  net_http_get(const char *host, const char *path, char *buf, unsigned cap);
