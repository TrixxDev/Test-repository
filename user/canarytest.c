/* Phase 19.2 acceptance: prove BOTH stack-canary layers fire.
 *
 * Phase 1 (userspace, recoverable): fork() a child that overruns a small
 * local buffer. The child's own -fstack-protector-strong epilogue check
 * calls user/libc/ssp.c's __stack_chk_fail(), which prints and _exit(134)s
 * -- the parent wait()s and reports the status. The OS survives: one
 * process corrupting its own stack kills that process, nothing else.
 *
 * Phase 2 (kernel, fatal by design): SYS_DEBUG_STACK_SMASH overruns a
 * 64-byte buffer inside a kernel frame by 64 bytes -- enough to clobber
 * the compiler canary, nowhere near the guard page -- and the kernel halts
 * with "KERNEL STACK SMASHING DETECTED". This call never returns, so
 * tools/canary_qemu.py greps the serial log rather than trusting an exit
 * code (same convention as kstacktest/guard_page_qemu.py). */
#include "libc.h"

static int __attribute__((noinline)) user_smash(void)
{
    char buf[32];
    /* Volatile length so the optimizer can't prove (and delete) the
     * out-of-bounds write; 64 bytes past a 32-byte buffer reaches the
     * canary and saved return address, nothing beyond this stack page. */
    static volatile unsigned n = 64;
    volatile char *p = buf;
    for (unsigned i = 0; i < n; i++)
        p[i] = 0x41;
    return buf[0];
}

int main(void)
{
    printf("[canarytest] phase 1: userspace canary, smashing in a fork()ed child...\n");
    int pid = fork();
    if (pid == 0) {
        user_smash();
        printf("[canarytest] FAIL: child returned from user_smash() -- user canary did not fire\n");
        _exit(0);
    }
    int status = -1;
    wait(&status);
    printf("[canarytest] child exit status=%d (134 = canary abort)\n", status);

    printf("[canarytest] phase 2: kernel canary via debug_stack_smash() -- system will halt...\n");
    debug_stack_smash();
    printf("[canarytest] FAIL: debug_stack_smash() returned -- kernel canary did not fire\n");
    return 1;
}
