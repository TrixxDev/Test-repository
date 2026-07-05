/* Phase 18.5.2 acceptance: prints the kernel-wide profiling counters
 * (SYS_PROFSTAT) so a QEMU test can confirm real work actually drives them,
 * not just that the syscall compiles. Usage: profstat */
#include "libc.h"

int main(void)
{
    struct kernel_prof p;
    if (profstat(&p) != 0) {
        printf("profstat() failed\n");
        return 1;
    }

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
    return 0;
}
