/* Phase 18.5.2 acceptance: prints the kernel-wide profiling counters
 * (SYS_PROFSTAT) so a QEMU test can confirm real work actually drives them,
 * not just that the syscall compiles. Usage: profstat
 *
 * Phase 18.5.5: also dumps SYS_NETSTAT's existing struct net_stats (rx_irqs
 * alongside rx_packets) -- both were already tracked by drivers/virtio_net.c
 * for the Settings app's network panel, just never next to the kernel_prof
 * counters above in one place. Comparing rx_irqs to how many of those
 * tcp_tick_calls (== net_poll() calls) actually found a packet is the direct
 * way to tell whether data delivery is paced by the wire or by how often
 * something happens to call net_poll(). */
#include "libc.h"

int main(void)
{
    struct kernel_prof p;
    if (profstat(&p) != 0) {
        printf("profstat() failed\n");
        return 1;
    }
    struct net_stats ns;
    memset(&ns, 0, sizeof(ns));
    netstat(&ns);

    printf("sched_switches=%u\n", p.sched_switches);
    printf("wait_blocks=%u\n", p.wait_blocks);
    printf("tcp_input_calls=%u tcp_input_us=%u\n", p.tcp_input_calls, p.tcp_input_us);
    printf("tcp_tick_calls=%u tcp_tick_us=%u\n", p.tcp_tick_calls, p.tcp_tick_us);
    printf("fat_read_calls=%u fat_read_us=%u\n", p.fat_read_calls, p.fat_read_us);
    printf("fat_write_calls=%u fat_write_us=%u\n", p.fat_write_calls, p.fat_write_us);
    printf("memcpy_calls=%u memcpy_bytes=%u\n", p.memcpy_calls, p.memcpy_bytes);
    printf("tcp_read_calls=%u tcp_read_iters=%u tcp_read_bytes=%u\n",
           p.tcp_read_calls, p.tcp_read_iters, p.tcp_read_bytes);
    printf("tcp_wait_us=%u\n", p.tcp_wait_us);
    printf("tcp_connect_iters=%u tcp_write_iters=%u tcp_close_iters=%u\n",
           p.tcp_connect_iters, p.tcp_write_iters, p.tcp_close_iters);
    printf("rx_irqs=%u rx_packets=%u rx_bytes=%u rx_dropped=%u rx_errors=%u\n",
           ns.rx_irqs, ns.rx_packets, ns.rx_bytes, ns.rx_dropped, ns.rx_errors);
    printf("tx_packets=%u tx_bytes=%u\n", ns.tx_packets, ns.tx_bytes);
    return 0;
}
