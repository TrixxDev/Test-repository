/* Network stack entry points (kernel side).
 *
 * Layering: virtio_net (transport) -> eth (framing/dispatch) -> arp / ipv4 ...
 * net_poll() pumps received frames up through eth_input(); for now it is driven
 * from active waits (the ARP self-test, later a net thread/daemon). */
#pragma once

void net_init(void);        /* initialise the protocol layers (ARP cache, ...) */
void net_poll(void);        /* drain the RX ring into eth_input() */
void net_selftest(void);    /* Phase 4/5 proof: Ethernet + ARP scenarios */
