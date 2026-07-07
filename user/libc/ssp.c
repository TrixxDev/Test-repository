/* Phase 19.2: userspace stack-smashing protector runtime. Every user
 * program (and the whole freestanding TLS/HTTP stack compiled via UCFLAGS)
 * now builds with -fstack-protector-strong; clang references the global
 * __stack_chk_guard for the bare i686-elf target, and this provides it.
 *
 * Unlike the kernel's (arch/i386/stack_protector.c), the userspace guard is
 * a FIXED value: crt0 jumps straight to main with no libc init hook to seed
 * it from, and Aurora has no getrandom()-style syscall yet. That is an
 * honest trade-off, stated plainly: this canary reliably catches ACCIDENTAL
 * overflows (the overwhelmingly common case -- e.g. the h2_test check_hex()
 * bug 17.5.1 found), but a targeted exploit that can read the binary knows
 * the value. Per-process entropy belongs to the future ASLR phase.
 *
 * A smashed process is killed via _exit(134) -- 134 = 128+SIGABRT by Unix
 * convention, and distinctive enough that a parent's wait() status (or the
 * shell's "[exit 134]") reads unambiguously as "canary abort", which is
 * exactly what user/canarytest.c and tools/canary_qemu.py key on. The
 * kernel stays untouched: one process corrupting its own stack is a bug in
 * that program, not a system halt. */
#include <stdint.h>
#include "../libc.h"

uint32_t __stack_chk_guard = 0xC3A57E19u;

void __attribute__((noreturn)) __stack_chk_fail(void)
{
    printf("*** stack smashing detected: this process overflowed a stack "
           "buffer -- aborting\n");
    _exit(134);
    for (;;) ;      /* _exit never returns; keep noreturn honest for clang */
}
