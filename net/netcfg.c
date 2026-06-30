/* Runtime network configuration — see netcfg.h. */
#include "netcfg.h"
#include "inet.h"

struct net_config g_net_config;

void netcfg_init(void)
{
    netcfg_reset_static();
}

void netcfg_set(uint32_t ip, uint32_t mask, uint32_t gateway, uint32_t dns0, uint32_t dns1)
{
    g_net_config.ip      = ip;
    g_net_config.mask    = mask;
    g_net_config.gateway = gateway;
    g_net_config.dns[0]  = dns0;
    g_net_config.dns[1]  = dns1;
}

void netcfg_reset_static(void)
{
    /* QEMU user-mode (SLIRP) defaults: guest 10.0.2.15/24, gateway 10.0.2.2,
     * DNS 10.0.2.3 -- unchanged from every phase before 15.3. */
    netcfg_set(IP4(10, 0, 2, 15), IP4(255, 255, 255, 0), IP4(10, 0, 2, 2),
               IP4(10, 0, 2, 3), 0);
}
