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
/* Block the current thread for `nticks` PIT ticks (woken from the timer IRQ).
 * Returns when the deadline passes; safe to call with interrupts on. */
void thread_sleep_ticks(uint32_t nticks);
void thread_zombie_and_yield(void);  /* mark current ZOMBIE and switch away */
void thread_free(thread_t *t);       /* unlink + free a non-running thread */

/* Phase 18.1: the one blocking primitive every subsystem that waits for an
 * external event (console/serial input, a pipe, a socket, the filesystem
 * later) is meant to share, instead of each hand-rolling its own single
 * "thread_t *waiter" field. A queue is a FIFO of wait_node_t entries.
 *
 * Phase 18.3: a queue holds *nodes*, not threads directly, so one thread can
 * be linked into several queues at once (needed for waiting on several fds
 * for whichever becomes ready first) -- each membership is its own node.
 * The single-queue calls below (wait_enqueue/wait_wake_one/wait_wake_all/
 * wait_event_timeout) are unchanged in signature and behavior; they now use
 * a node embedded in the thread itself under the hood, so every 18.1/18.2
 * caller (console, pipe, the TCP socket) needed no changes at all. */
typedef struct wait_node {
    thread_t *thread;
    struct wait_queue *wq;      /* which queue this node is linked into, or NULL */
    struct wait_node *next, *prev;
    int fired;                  /* Phase 18.3: set when wait_wake_one/all fires
                                  * this node, so a multi-queue waiter can tell
                                  * which of its several queues woke it */
} wait_node_t;

typedef struct wait_queue {
    wait_node_t *head, *tail;
} wait_queue_t;

#define WAIT_QUEUE_INIT { 0, 0 }
void wait_queue_init(wait_queue_t *wq);

/* Adds the current thread to `wq` and blocks it (yields; never returns until
 * woken). Caller must hold interrupts off across checking its own wait
 * condition and calling this, exactly like thread_block()'s contract --
 * otherwise a wakeup between the check and the enqueue is lost. Returns
 * with interrupts still off. */
void wait_enqueue(wait_queue_t *wq);

/* Wake the oldest waiter on `wq` (FIFO) / every waiter on `wq`, if any.
 * Same convention as thread_wake(): safe to call from any IRQ handler as-is
 * (interrupt gates already run with IF=0), or from normal thread context
 * wrapped in your own cli/sti. */
void wait_wake_one(wait_queue_t *wq);
void wait_wake_all(wait_queue_t *wq);

/* Like wait_enqueue(), but also gives up after `timeout_ms` milliseconds if
 * nobody woke it first (0 means wait forever, same as wait_enqueue()).
 * Returns 1 if woken via wait_wake_one()/wait_wake_all(), 0 if it timed out
 * (in which case it has already removed itself from `wq`). Same
 * interrupts-off contract as wait_enqueue(). */
int wait_event_timeout(wait_queue_t *wq, uint32_t timeout_ms);

/* ---- Phase 18.3: multi-queue waiting (one thread, several event sources) ----
 * A caller (e.g. a wait-for-any-of-these-fds syscall) owns an array of
 * wait_node_t, one per source it cares about -- typically stack-allocated,
 * living only for the duration of one wait. */

/* Links `node` into `wq` for the current thread; does not block. Caller
 * holds interrupts off. `node`'s storage is the caller's; it must outlive
 * the wait (until wait_node_remove()). */
void wait_node_add(wait_node_t *node, wait_queue_t *wq);

/* Unlinks `node` from whatever queue it's on, if any -- safe to call even if
 * wait_wake_one()/wait_wake_all() already removed it (idempotent). Caller
 * holds interrupts off. */
void wait_node_remove(wait_node_t *node);

/* Blocks the current thread until something calls thread_wake() on it --
 * typically wait_wake_one()/wait_wake_all() firing one of its already-added
 * wait_node_t's -- or `timeout_ms` elapses (0 = forever). Unlike
 * wait_event_timeout(), this isn't tied to any one queue, so it can't tell
 * you *why* you woke up: the caller checks its own nodes' `.fired` flags
 * afterward (and must wait_node_remove() each one itself). Caller holds
 * interrupts off; returns with interrupts off. */
void wait_block_timeout(uint32_t timeout_ms);

thread_t *thread_current(void);
void  thread_set_proc(thread_t *t, void *proc);
void *thread_get_proc(thread_t *t);
void *thread_start_arg(thread_t *t);
void  thread_set_pd(thread_t *t, uint32_t pd_phys);
uint32_t thread_kstack_top(thread_t *t);

void scheduler_enable(void);
void scheduler_disable(void);
int  thread_count(void);
