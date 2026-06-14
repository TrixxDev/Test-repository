/* Preemptive round-robin scheduler over threads.
 *
 * A kernel thread runs in ring 0 in the shared kernel address space. A user
 * thread starts in ring 3 in its own address space (per-process page
 * directory). The timer interrupt drives preemption. */
#pragma once
#include <stdint.h>

typedef void (*thread_entry_t)(void);

void scheduler_init(void);

/* Spawn a ring-0 thread running `entry` in the kernel address space. */
int thread_create_kernel(thread_entry_t entry);

/* Spawn a ring-3 thread: address space `pd_phys`, starting at `entry` with the
 * given user stack top. */
int thread_create_user(uint32_t pd_phys, uint32_t entry, uint32_t user_stack);

void schedule(void);
void thread_exit(void);     /* terminate the calling thread; never returns */

void scheduler_enable(void);
void scheduler_disable(void);
int  thread_count(void);
