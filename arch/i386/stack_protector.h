/* Phase 19.2: stack canaries -- the compiler stack-smashing protector's
 * freestanding runtime, plus the per-thread canary values the scheduler
 * swaps into it.
 *
 * The whole kernel now builds with -fstack-protector-strong: every function
 * with a local array (or an address-taken local) gets a hidden canary word
 * pushed between its locals and its saved ebp/return address, and a check on
 * return that calls __stack_chk_fail() if it changed. This catches the class
 * the guard page (Phase 18.5.6) architecturally can't: an overflow that
 * corrupts the CURRENT frame's return address but never leaves the mapped
 * stack pages. Together they layer: canary = in-page corruption caught at
 * function return, guard page = past-the-end overflow caught at the very
 * first out-of-bounds write.
 *
 * The guard the compiler compares against is the single global
 * __stack_chk_guard (clang's behavior for a bare i686-elf target). To make
 * the canary per-thread anyway -- so one thread's leaked/observed canary
 * says nothing about another's -- the scheduler stores each thread's own
 * value (stack_canary_for()) into the global on every switch-in. That is
 * coherent because a frame's canary is only ever pushed and checked while
 * its own thread is executing, and the global always holds that thread's
 * value during those windows (Linux does the same thing on !SMP x86). */
#pragma once
#include <stdint.h>

/* The live guard every -fstack-protector frame pushes and re-checks.
 * Starts as a fixed placeholder so code running before
 * stack_protector_init() is still checked (just less unpredictably);
 * the scheduler overwrites it with the incoming thread's canary at every
 * context switch once threading starts. */
extern uint32_t __stack_chk_guard;

/* Reseed the boot entropy + __stack_chk_guard from the TSC. Call once,
 * as the very first boot step -- only kernel_main() (which never returns,
 * so its own canary is never re-checked) may have a frame alive across
 * the reseed, or an in-flight function would compare its old copy against
 * the new value and die with a false positive. */
void stack_protector_init(void);

/* Deterministic per-thread canary: hash(boot seed, tid, stack base) -- no
 * RNG dependency, reproducible within a boot, different across boots (TSC
 * seed) and across threads (tid/base). Never returns 0 (an all-zero canary
 * is the one value a zero-fill overflow would "restore" unnoticed). */
uint32_t stack_canary_for(uint32_t tid, uint32_t stack_base);

/* Called by compiler-emitted epilogue checks on a mismatch. Prints the
 * failing return site and halts -- the frame it would return through is
 * known-corrupt, so there is nothing safe to resume. */
void __stack_chk_fail(void) __attribute__((noreturn));

/* Phase 19.2 acceptance hook (SYS_DEBUG_STACK_SMASH): deliberately overrun
 * a small local buffer far enough to hit the frame canary but NOT the guard
 * page, proving the canary layer fires on its own. Never returns if the
 * protector works (the smashed function's epilogue check halts). */
int sys_debug_stack_smash(void);
