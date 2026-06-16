/* Preemptive round-robin scheduler over threads with run states.
 *
 * A kernel thread runs in ring 0 in the shared kernel address space. A user
 * thread runs in ring 3 in its process's address space. Threads can block
 * (e.g. waiting for input or a child) and be woken later. */
#pragma once
#include <stdint.h>

typedef void (*thread_entry_t)(void);

/* Opaque thread handle. */
typedef struct thread thread_t;

void scheduler_init(void);

/* Spawn a ring-0 thread running `entry` in the kernel address space. */
thread_t *thread_create_kernel(thread_entry_t entry);

/* Spawn a ring-3 thread: address space `pd_phys`, dropping to ring 3 at
 * `entry` with the given user stack top on first run. */
thread_t *thread_create_user(uint32_t pd_phys, uint32_t entry, uint32_t user_stack);

/* Spawn a thread that first runs the kernel function `start_eip` (used by fork
 * to install a trampoline that returns to ring 3). `arg` is retrievable via
 * thread_start_arg(). */
thread_t *thread_create_trampoline(uint32_t pd_phys, uint32_t start_eip, void *arg);

/* Make a thread created via the user/trampoline helpers runnable. */
void thread_start(thread_t *t);

void schedule(void);          /* yield to another runnable thread */
void thread_block(void);      /* mark current BLOCKED + yield (call with IF off) */
void thread_wake(thread_t *t);
void thread_zombie_and_yield(void);  /* mark current ZOMBIE and switch away */
void thread_free(thread_t *t);       /* unlink + free a non-running thread */

thread_t *thread_current(void);
void  thread_set_proc(thread_t *t, void *proc);
void *thread_get_proc(thread_t *t);
void *thread_start_arg(thread_t *t);
void  thread_set_pd(thread_t *t, uint32_t pd_phys);
uint32_t thread_kstack_top(thread_t *t);

void scheduler_enable(void);
void scheduler_disable(void);
int  thread_count(void);
