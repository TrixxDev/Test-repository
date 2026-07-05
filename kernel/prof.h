/* Phase 18.5.2: kernel-wide profiling counters -- see struct kernel_prof in
 * syscall_abi.h for what's tracked and why. One shared global, incremented
 * directly by each instrumented subsystem (the same "no abstraction layer,
 * just a flat stats struct" style net/tcp.c's own `stats` already uses). */
#pragma once
#include "syscall_abi.h"        /* struct kernel_prof */

extern struct kernel_prof g_kprof;

/* Snapshot the counters (a plain struct copy; no locking -- same single-CPU,
 * best-effort-consistency assumption every other stats snapshot here makes). */
void kprof_get(struct kernel_prof *out);
