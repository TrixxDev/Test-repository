/* Runtime network configuration — Phase 15.3.4.
 *
 * The single source of truth for our IP, subnet mask, gateway and DNS servers.
 * Every consumer (arp/ipv4/tcp/dns, via the IP_LOCAL/IP_GATEWAY macros in
 * inet.h) reads through here instead of a compile-time constant, so static
 * configuration, a DHCP lease (net/dhcp.c) and -- later -- a GUI "manual
 * network settings" panel differ only in who calls netcfg_set()/
 * netcfg_reset_static(), never in the stack itself. */
#pragma once
#include <stdint.h>

struct net_config {
    uint32_t ip;
    uint32_t mask;
    uint32_t gateway;
    uint32_t dns[2];        /* dns[1] may be 0 (no second server) */
};

extern struct net_config g_net_config;

/* Seed g_net_config with the QEMU SLIRP static defaults (10.0.2.15/24, gateway
 * 10.0.2.2, DNS 10.0.2.3). Called once from net_init(), before DHCP runs --
 * a NIC-less boot, a DHCP timeout/failure, or no-DHCP-attempted all leave the
 * stack in exactly the configuration it has always had. */
void netcfg_init(void);

/* Install a new live configuration (a successful DHCP lease). dns1 may be 0. */
void netcfg_set(uint32_t ip, uint32_t mask, uint32_t gateway, uint32_t dns0, uint32_t dns1);

/* Restore the static SLIRP defaults (the DHCP failure/lease-loss fallback). */
void netcfg_reset_static(void);
