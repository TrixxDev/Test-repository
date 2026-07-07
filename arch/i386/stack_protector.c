/* Phase 19.2: stack-smashing protector runtime -- see stack_protector.h for
 * the design (why the compiler guard is one global, and how the scheduler
 * makes it per-thread anyway by swapping it at context switch). */
#include "stack_protector.h"
#include "kio.h"

/* Non-zero placeholder so pre-init code is still protected. Deliberately
 * contains no 0x00 byte: a NUL would let a string-copy overflow terminate
 * exactly on the canary and sneak past it. (The classic "terminator canary"
 * argues the opposite trade-off -- a leading NUL STOPS str* overflows from
 * ever writing beyond it -- but on i386 that spends a quarter of an already
 * small 32-bit canary; this kernel keeps all 32 bits of unpredictability.) */
uint32_t __stack_chk_guard = 0xC3A57E19u;

static uint32_t boot_seed = 0x41757230u;   /* "Aur0" -- fallback if no TSC */

uint32_t stack_canary_for(uint32_t tid, uint32_t stack_base)
{
    /* Knuth multiplicative mix of the inputs, then an xorshift avalanche so
     * adjacent tids/stack bases (they ARE adjacent -- slots are sequential)
     * still produce unrelated-looking canaries. */
    uint32_t x = boot_seed ^ (tid * 2654435761u) ^ (stack_base * 0x9E3779B9u);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x ? x : 0xDEADC0DEu;
}

/* no_stack_protector: this function swaps the guard out from under itself;
 * its own frame must not carry a canary or the epilogue would compare a
 * copy of the OLD guard against the NEW one and halt on a false positive. */
__attribute__((no_stack_protector))
void stack_protector_init(void)
{
    /* CPUID.1:EDX bit 4 = TSC present (it always is on anything this kernel
     * boots on, but the fallback costs nothing). Even a raw, uncalibrated
     * TSC read this early is fine as a seed -- cycle counts at boot vary
     * run to run by far more than an attacker can observe from inside. */
    uint32_t eax, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=d"(edx) : "a"(1) : "ebx", "ecx");
    if (edx & (1u << 4)) {
        uint32_t lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        boot_seed ^= lo ^ (hi * 0x85EBCA6Bu);
    }
    __stack_chk_guard = stack_canary_for(0xB007u, (uint32_t)&boot_seed);
}

void __stack_chk_fail(void)
{
    /* The return address of THIS call sits in the smashed function's
     * epilogue -- the one place the corruption is guaranteed not to have
     * reached (the call pushed it just now), so it reliably names the
     * function that overflowed. */
    kprintf("\n*** KERNEL STACK SMASHING DETECTED: a stack canary was overwritten\n"
            "    (caught at function return, before the corrupted return address\n"
            "    could be used; failing function is at eip~0x%x)\n",
            (uint32_t)__builtin_return_address(0));
    kprintf("*** System halted.\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* ---- Phase 19.2 acceptance hook ---------------------------------------- */

/* The overrun length is read through a volatile so the optimizer cannot see
 * the out-of-bounds write coming (it would otherwise be entitled to delete
 * the whole function as UB). 128 bytes past a 64-byte buffer reaches the
 * canary and the saved ebp/return address but stays thousands of bytes away
 * from the guard page -- if this halts, it was the canary, not Phase 18.5.6. */
static volatile unsigned smash_len = 128;

static int __attribute__((noinline)) smash_frame(void)
{
    char buf[64];
    volatile char *p = buf;
    for (unsigned i = 0; i < smash_len; i++)
        p[i] = 0x41;
    return buf[0] + buf[63];    /* keep buf observable */
}

int sys_debug_stack_smash(void)
{
    kprintf("[kernel] debug_stack_smash: deliberately overrunning a 64-byte frame buffer by 64\n");
    int r = smash_frame();      /* never returns: its epilogue canary check fires */
    kprintf("[kernel] debug_stack_smash: smash_frame RETURNED (r=%d) -- canary did NOT fire\n", r);
    return r;
}
