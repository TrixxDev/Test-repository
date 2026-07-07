#include "scheduler.h"
#include "kheap.h"
#include "pit.h"
#include "gdt.h"
#include "paging.h"
#include "pmm.h"
#include "prof.h"
#include "kio.h"
#include "stack_protector.h"
#include <stdint.h>
#include <stddef.h>

#define STACK_SIZE 8192

/* Guard pages: every alloc_thread() kernel stack (kernel threads and every
 * user/trampoline thread's ring-0 stack alike, per thread_create_user()/
 * thread_create_trampoline() both routing through alloc_thread()) now lives
 * in its own dedicated, page-mapped 3-page slot -- one deliberately UNMAPPED
 * guard page (vmm_map_page() is never called for it) directly below
 * STACK_SIZE/PAGE_SIZE mapped stack pages -- instead of an ordinary
 * kmalloc() block sitting wherever the heap's first-fit allocator happened
 * to place it, back-to-back with other heap objects. Before this, a stack
 * overflow didn't fault at all: it silently overwrote whatever kmalloc'd
 * memory sat next to it (exactly what happened in fs/fat32.c's
 * fat_write_impl()/fat_update_dirent() double-cbuf bug -- see docs/SECURITY.md
 * "Step 18.5"). Now the very first out-of-bounds write faults immediately.
 *
 * The slot area (0xF0000000+) sits inside the kernel-space PD range every
 * process's page directory shares by reference with vmm_kernel_directory()
 * (paging.c's vmm_create_address_space() aliases PD indices 768-1022 across
 * every address space), so vmm_map_page()/vmm_unmap_page() here take effect
 * for every process regardless of which CR3 happens to be loaded when a
 * thread is created or freed -- the same reason kernel/process.c's own user-
 * stack mapping doesn't need to switch address spaces first.
 *
 * Known gap: the boot thread (main_thread/main_kstack below) is a singleton
 * static array, not routed through alloc_thread(), and is NOT guarded --
 * matches its pre-existing "not page-aligned, half-size" special case.
 *
 * A same-privilege (ring0->ring0) page fault doesn't switch stacks, so the
 * CPU's own exception-frame push happens using the already-invalid ESP --
 * in practice this ALWAYS re-faults (confirmed empirically: an ordinary
 * single-push-at-a-time overflow escalates page-fault -> double-fault ->
 * triple-fault every time, not just for some rare "oversteps by a lot"
 * case, since the delivery frame's first push targets the exact same
 * address the original instruction just failed to write). Vector 8 (#DF)
 * is therefore wired as a TASK GATE to a dedicated stack (arch/i386/gdt.c's
 * df_tss, arch/i386/isr.c's df_handler_entry()) instead of a normal
 * interrupt gate, so the diagnostic always has a valid stack to run on
 * regardless of how the original thread's stack broke. */
#define KSTACK_PAGES        (STACK_SIZE / PAGE_SIZE)     /* 2 */
#define KSTACK_SLOT_PAGES   (KSTACK_PAGES + 1)           /* +1 guard page */
#define KSTACK_AREA_BASE    0xF0000000u                  /* shared kernel range,
                                                            * far from the heap
                                                            * (0xD0000000+) and
                                                            * the recursive
                                                            * self-map (0xFFC00000) */
#define MAX_KSTACK_SLOTS    64                            /* MAX_PROCS (32) plus
                                                            * headroom for kernel
                                                            * threads + not-yet-
                                                            * freed zombies */

static uint8_t kstack_slot_used[MAX_KSTACK_SLOTS];

static int kstack_slot_alloc(void)
{
    for (int i = 0; i < MAX_KSTACK_SLOTS; i++) {
        if (!kstack_slot_used[i]) {
            kstack_slot_used[i] = 1;
            return i;
        }
    }
    return -1;                 /* every slot in use */
}

static void kstack_slot_free(int slot)
{
    if (slot >= 0 && slot < MAX_KSTACK_SLOTS)
        kstack_slot_used[slot] = 0;
}

enum { TS_READY, TS_BLOCKED, TS_SLEEPING, TS_ZOMBIE };

struct thread {
    uint32_t esp;           /* saved kernel stack pointer (must stay first) */
    uint32_t pd_phys;       /* address space (CR3 value) */
    uint32_t kstack_top;    /* ring-0 stack top, loaded into TSS.esp0 */
    void    *kstack;        /* base of the allocated kernel stack (NULL for
                               * the boot thread, which uses main_kstack[]
                               * instead and has no guard page) */
    int      kstack_slot;   /* index into kstack_slot_used[], or -1 if this
                               * thread's stack isn't guard-paged (boot thread) */
    uint32_t stack_canary;  /* Phase 19.2: this thread's own canary value.
                               * Two uses: (1) do_switch() writes it into the
                               * global __stack_chk_guard on switch-in, so
                               * every -fstack-protector frame this thread
                               * pushes checks against a per-thread value;
                               * (2) the same value is stored in the lowest
                               * word of the kernel stack (directly above the
                               * guard page) as a stack-END canary, checked
                               * at context switch / syscall exit / free --
                               * a cheap early sensor for writes that reached
                               * the very bottom without crossing into the
                               * guard page. */
    int      tid;
    int      state;
    void    *proc;          /* owning process (PCB), or NULL for kernel threads */
    void    *start_arg;     /* argument for trampoline threads */
    uint32_t user_entry;    /* first-run info for user threads */
    uint32_t user_stack;
    struct thread *next;
    struct thread *prev;
    wait_node_t wnode;      /* Phase 18.1/18.3: this thread's own membership
                              * node for the single-queue wait calls
                              * (wait_enqueue/wait_event_timeout) -- a separate
                              * link from next/prev, which is the scheduler's
                              * own ring and never changes membership when a
                              * thread blocks. Phase 18.3's multi-queue waits
                              * use their own, separately-allocated nodes
                              * instead of this one. */
};

extern void switch_task(uint32_t *old_esp_out, uint32_t new_esp);
extern void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top);

static thread_t *current;
static thread_t  main_thread;
static uint8_t   main_kstack[4096] __attribute__((aligned(16)));
static int       next_tid;
static int       nthreads;
static volatile int enabled;

/* Sleeping threads waiting on a timer deadline (in PIT ticks). The PIT tick hook
 * wakes any whose deadline has passed before it reschedules — this lets a thread
 * block for a duration without busy-waiting (used by a userspace render ticker). */
#define MAX_SLEEPERS 8
static struct { thread_t *t; uint32_t wake; int used; } sleepers[MAX_SLEEPERS];

static void scheduler_tick(void);   /* PIT hook: wake due sleepers, then schedule */
static void sleepers_cancel(thread_t *t);   /* cancel t's pending sleepers[] deadline, if any */
static int  sleepers_arm(thread_t *t, uint32_t nticks);   /* arm t's sleepers[] deadline */

/* First thing a freshly created user thread runs (in ring 0). */
static void user_thread_start(void)
{
    enter_user_mode(current->user_entry, current->user_stack);
}

void scheduler_init(void)
{
    /* Same reason lib/kheap.c's kheap_init() pre-creates its own range's page
     * tables: vmm_create_address_space() clones the shared high-memory PDEs
     * by VALUE from whatever page directory is active at that moment (it
     * copies through the recursive self-map, not from one canonical kernel
     * PD), so a page table this region needs must already exist before the
     * first process is created, or a process created before the kstack
     * area's table happened to get allocated would silently be missing it
     * (a page fault into an address that's actually meant to be a live
     * kernel stack -- not a page-table read here would be too late). */
    vmm_ensure_table(KSTACK_AREA_BASE);

    main_thread.tid        = next_tid++;
    main_thread.pd_phys    = vmm_kernel_directory();
    main_thread.kstack_top = (uint32_t)(main_kstack + sizeof(main_kstack));
    main_thread.kstack     = NULL;
    main_thread.kstack_slot = -1;   /* boot thread: no guard page, see above */
    /* Phase 19.2: the boot thread's canary must equal the CURRENT global
     * guard, not a fresh value -- its frames (kernel_main and everything
     * under it) were already pushed against __stack_chk_guard as reseeded
     * by stack_protector_init(), and do_switch() will restore this value
     * every time the boot thread is switched back in. A different value
     * here would make the first process_wait() resume die on a false
     * canary mismatch. */
    main_thread.stack_canary = __stack_chk_guard;
    main_thread.state      = TS_READY;
    main_thread.proc       = NULL;
    main_thread.next       = &main_thread;
    main_thread.prev       = &main_thread;
    main_thread.wnode.thread = &main_thread;
    current = &main_thread;
    nthreads = 1;
    pit_set_tick_hook(scheduler_tick);
}

static void link_thread(thread_t *t)
{
    __asm__ volatile("cli");
    t->next = current;
    t->prev = current->prev;
    current->prev->next = t;
    current->prev = t;
    nthreads++;
    __asm__ volatile("sti");
}

/* Build a fresh kernel stack whose top frame mimics switch_task's saved state,
 * so the first switch "returns" into `start_eip`. */
static uint32_t build_stack(void *base, uint32_t start_eip)
{
    uint32_t *sp = (uint32_t *)((uint8_t *)base + STACK_SIZE);
    *(--sp) = (uint32_t)thread_zombie_and_yield;  /* if start_eip ever returns */
    *(--sp) = start_eip;               /* eip restored by switch_task's ret */
    *(--sp) = 0x202;                   /* eflags (IF=1) restored by popf */
    *(--sp) = 0;                       /* ebp */
    *(--sp) = 0;                       /* ebx */
    *(--sp) = 0;                       /* esi */
    *(--sp) = 0;                       /* edi */
    return (uint32_t)sp;
}

static thread_t *alloc_thread(uint32_t pd_phys, uint32_t start_eip)
{
    thread_t *t = (thread_t *)kmalloc(sizeof(thread_t));
    if (!t)
        return NULL;

    int slot = kstack_slot_alloc();
    if (slot < 0) {
        kfree(t);
        return NULL;
    }
    /* Slot layout: [guard page, left unmapped] [KSTACK_PAGES mapped pages]. */
    uint32_t slot_base = KSTACK_AREA_BASE + (uint32_t)slot * KSTACK_SLOT_PAGES * PAGE_SIZE;
    uint32_t stack_va   = slot_base + PAGE_SIZE;
    int mapped;
    for (mapped = 0; mapped < KSTACK_PAGES; mapped++) {
        uint32_t phys = pmm_alloc_frame();
        if (!phys)
            break;
        vmm_map_page(stack_va + (uint32_t)mapped * PAGE_SIZE, phys, PAGE_PRESENT | PAGE_WRITE);
    }
    if (mapped < KSTACK_PAGES) {                /* out of physical memory: unwind */
        for (int i = 0; i < mapped; i++) {
            uint32_t va = stack_va + (uint32_t)i * PAGE_SIZE;
            uint32_t phys = vmm_get_physical(va);
            vmm_unmap_page(va);
            if (phys)
                pmm_free_frame(phys);
        }
        kstack_slot_free(slot);
        kfree(t);
        return NULL;
    }

    t->kstack       = (void *)stack_va;
    t->kstack_slot  = slot;
    t->tid        = next_tid++;
    /* Phase 19.2: per-thread canary (see the struct field comment), plus a
     * copy in the stack's lowest word -- the stack-end canary. build_stack()
     * only touches the top of the stack, so this word survives until
     * something writes all the way down to the last 4 bytes above the guard
     * page. Costs the stack its bottom word of usable space, nothing else. */
    t->stack_canary = stack_canary_for((uint32_t)t->tid, stack_va);
    *(uint32_t *)stack_va = t->stack_canary;
    t->pd_phys    = pd_phys;
    t->kstack_top = stack_va + STACK_SIZE;
    t->state      = TS_READY;
    t->proc       = NULL;
    t->start_arg  = NULL;
    t->wnode.thread = t;
    t->wnode.wq   = NULL;
    t->wnode.next = t->wnode.prev = NULL;
    t->wnode.fired = 0;
    t->esp        = build_stack(t->kstack, start_eip);
    return t;
}

thread_t *thread_create_kernel(thread_entry_t entry)
{
    thread_t *t = alloc_thread(vmm_kernel_directory(), (uint32_t)entry);
    if (t)
        link_thread(t);
    return t;
}

/* User threads are created BLOCKED and linked into the scheduler, but not run
 * until thread_start() wakes them. This lets the caller finish wiring up the
 * owning process (thread->proc) before the thread can be scheduled. */
thread_t *thread_create_user(uint32_t pd_phys, uint32_t entry, uint32_t user_stack)
{
    thread_t *t = alloc_thread(pd_phys, (uint32_t)user_thread_start);
    if (!t)
        return NULL;
    t->user_entry = entry;
    t->user_stack = user_stack;
    t->state = TS_BLOCKED;
    link_thread(t);
    return t;
}

thread_t *thread_create_trampoline(uint32_t pd_phys, uint32_t start_eip, void *arg)
{
    thread_t *t = alloc_thread(pd_phys, start_eip);
    if (!t)
        return NULL;
    t->start_arg = arg;
    t->state = TS_BLOCKED;
    link_thread(t);
    return t;
}

/* Make a thread created BLOCKED runnable. */
void thread_start(thread_t *t)
{
    if (t)
        t->state = TS_READY;
}

static thread_t *next_runnable(thread_t *from)
{
    thread_t *t = from->next;
    while (t != from) {
        if (t->state == TS_READY)
            return t;
        t = t->next;
    }
    return (from->state == TS_READY) ? from : NULL;
}

/* Phase 19.2: halt if `t`'s stack-END canary (the word directly above its
 * guard page, written by alloc_thread()) has been overwritten. Checked at
 * the three cheap chokepoints -- context switch, syscall exit (via
 * thread_kstack_end_check()), and thread_free() -- NOT in any hot loop.
 * This is the early sensor for corruption that reached the very bottom of
 * the stack without crossing into the guard page; per-frame corruption
 * higher up is the compiler canary's job, crossing the boundary is the
 * guard page's. Halts rather than kills: a thread whose deepest kernel
 * frame area is corrupt cannot be safely unwound. */
static void kstack_end_check(thread_t *t)
{
    if (!t->kstack || *(uint32_t *)t->kstack == t->stack_canary)
        return;
    kprintf("\n*** KERNEL STACK END CANARY smashed: tid=%d wrote down to the last\n"
            "    word above its guard page without crossing it (found 0x%x,\n"
            "    expected 0x%x)\n",
            t->tid, *(uint32_t *)t->kstack, t->stack_canary);
    kprintf("*** System halted.\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

void thread_kstack_end_check(void)
{
    kstack_end_check(current);
}

static void do_switch(thread_t *prev, thread_t *next)
{
    g_kprof.sched_switches++;   /* Phase 18.5.2: a real context switch, not just a schedule() call */
    kstack_end_check(prev);
    /* Phase 19.2: kernel-stack high-water mark. We are still on prev's
     * stack right here, so live ESP (not the stale prev->esp, which
     * switch_task() only updates as it leaves) measures prev's true
     * current depth, scheduler frames included. */
    uint32_t esp_now;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_now));
    uint32_t used = prev->kstack_top - esp_now;
    if (used > g_kprof.kstack_max_used)
        g_kprof.kstack_max_used = used;
    /* Phase 19.2: make the compiler canary per-thread -- every frame next
     * has ever pushed stored ITS value of the guard, and no frame of next's
     * runs checks except while next is executing, so swapping here keeps
     * every thread's push/check pairs self-consistent (see
     * stack_protector.h). Must happen before switch_task(): the first
     * C prologue on the other side already reads the guard. */
    __stack_chk_guard = next->stack_canary;
    tss_set_kernel_stack(next->kstack_top);
    if (next->pd_phys != prev->pd_phys)
        vmm_switch_address_space(next->pd_phys);
    switch_task(&prev->esp, next->esp);
}

void schedule(void)
{
    if (!enabled)
        return;
    thread_t *prev = current;
    thread_t *next = next_runnable(prev);
    if (!next || next == prev)
        return;
    current = next;
    do_switch(prev, next);
}

void thread_block(void)
{
    /* Caller holds interrupts off to avoid a lost wakeup. */
    current->state = TS_BLOCKED;
    schedule();
}

void thread_wake(thread_t *t)
{
    if (t)
        t->state = TS_READY;
}

/* ---- Phase 18.1/18.3: wait queues -- the one shared blocking primitive ---- */

void wait_queue_init(wait_queue_t *wq)
{
    wq->head = wq->tail = NULL;
}

void wait_node_add(wait_node_t *node, wait_queue_t *wq)
{
    node->thread = current;
    node->wq = wq;
    node->fired = 0;
    node->next = NULL;
    node->prev = wq->tail;
    if (wq->tail)
        wq->tail->next = node;
    else
        wq->head = node;
    wq->tail = node;
}

void wait_node_remove(wait_node_t *node)
{
    wait_queue_t *wq = node->wq;
    if (!wq)
        return;                     /* already removed (idempotent) */
    if (node->prev) node->prev->next = node->next; else wq->head = node->next;
    if (node->next) node->next->prev = node->prev; else wq->tail = node->prev;
    node->next = node->prev = NULL;
    node->wq = NULL;
}

void wait_enqueue(wait_queue_t *wq)
{
    /* Caller holds interrupts off (same lost-wakeup contract as thread_block()). */
    wait_node_add(&current->wnode, wq);
    current->state = TS_BLOCKED;
    g_kprof.wait_blocks++;
    schedule();
}

void wait_wake_one(wait_queue_t *wq)
{
    wait_node_t *n = wq->head;
    if (!n)
        return;
    wait_node_remove(n);
    n->fired = 1;
    sleepers_cancel(n->thread);   /* a wait_event_timeout() waiter's backstop, if any */
    thread_wake(n->thread);
}

void wait_wake_all(wait_queue_t *wq)
{
    wait_node_t *n = wq->head;
    while (n) {
        wait_node_t *next = n->next;
        wait_node_remove(n);
        n->fired = 1;
        sleepers_cancel(n->thread);
        thread_wake(n->thread);
        n = next;
    }
}

void wait_block_timeout(uint32_t timeout_ms)
{
    /* Caller holds interrupts off. A table-full sleepers_arm() just means
     * "no timer backstop this time" -- the caller's own fd-readiness re-scan
     * loop (Phase 18.3's sys_wait_events()) still bounds the overall wait,
     * unlike wait_event_timeout() which promises a specific timeout. */
    if (timeout_ms)
        sleepers_arm(current, timeout_ms / 10);
    current->state = TS_BLOCKED;
    g_kprof.wait_blocks++;
    schedule();
}

/* PIT tick hook (IRQ0, interrupts off): wake any sleeper whose deadline has
 * passed, then run the normal preemptive scheduler. Signed compare so the tick
 * counter can wrap safely. */
static void scheduler_tick(void)
{
    uint32_t now = pit_ticks();
    for (int i = 0; i < MAX_SLEEPERS; i++)
        if (sleepers[i].used && (int32_t)(now - sleepers[i].wake) >= 0) {
            sleepers[i].t->state = TS_READY;
            sleepers[i].used = 0;
        }
    schedule();
}

/* Registers `t` to be woken at `pit_ticks() + nticks`, or degrades to a
 * plain yield if the (small, fixed) table is full. Shared by
 * thread_sleep_ticks() (pure duration sleep) and wait_event_timeout()
 * (a wait queue with a timeout backstop). Caller sets `t`'s state and calls
 * schedule() itself -- this only arms the deadline. */
static int sleepers_arm(thread_t *t, uint32_t nticks)
{
    int slot = -1;
    for (int i = 0; i < MAX_SLEEPERS; i++)
        if (!sleepers[i].used) { slot = i; break; }
    if (slot < 0)
        return -1;
    sleepers[slot].t    = t;
    sleepers[slot].wake = pit_ticks() + (nticks ? nticks : 1);
    sleepers[slot].used = 1;
    return slot;
}

/* Cancels `t`'s pending deadline, if any -- called whenever `t` is woken by
 * something other than the timeout itself, so a stale entry can't fire a
 * spurious wake later (or, worse, once `t` has been freed and its memory
 * reused for a different thread). */
static void sleepers_cancel(thread_t *t)
{
    for (int i = 0; i < MAX_SLEEPERS; i++)
        if (sleepers[i].used && sleepers[i].t == t)
            sleepers[i].used = 0;
}

void thread_sleep_ticks(uint32_t nticks)
{
    __asm__ volatile("cli");
    if (sleepers_arm(current, nticks) < 0) {   /* table full: degrade to a plain yield */
        __asm__ volatile("sti");
        schedule();
        return;
    }
    current->state = TS_SLEEPING;
    schedule();                     /* switch away; the tick hook wakes us */
    __asm__ volatile("sti");
}

int wait_event_timeout(wait_queue_t *wq, uint32_t timeout_ms)
{
    /* Caller holds interrupts off (same contract as wait_enqueue()). */
    if (timeout_ms == 0) {
        wait_enqueue(wq);
        return 1;
    }
    if (sleepers_arm(current, timeout_ms / 10) < 0)
        return 0;               /* timer table full -- don't risk an unbounded wait */

    wait_node_add(&current->wnode, wq);
    current->state = TS_BLOCKED;
    g_kprof.wait_blocks++;
    schedule();

    /* Resumed. wait_wake_one()/wait_wake_all() already remove+fire the node
     * (and cancel our sleepers[] slot) if THEY are what woke us; the PIT
     * tick hook's deadline does neither -- it only clears the slot. So
     * still being linked into wq means the timeout fired first. */
    if (current->wnode.wq == wq) {
        wait_node_remove(&current->wnode);
        return 0;
    }
    return 1;
}

void thread_zombie_and_yield(void)
{
    __asm__ volatile("cli");
    current->state = TS_ZOMBIE;

    thread_t *prev = current;
    thread_t *next = next_runnable(prev);   /* main thread is always runnable */
    current = next;

    kstack_end_check(prev);                 /* Phase 19.2: last chance to catch
                                             * corruption the dying thread did */
    __stack_chk_guard = next->stack_canary; /* Phase 19.2: same swap as do_switch() */
    tss_set_kernel_stack(next->kstack_top);
    if (next->pd_phys != prev->pd_phys)
        vmm_switch_address_space(next->pd_phys);

    uint32_t discard;
    switch_task(&discard, next->esp);       /* never returns */

    for (;;)
        __asm__ volatile("hlt");
}

void thread_free(thread_t *t)
{
    __asm__ volatile("cli");
    /* A forcibly killed thread (sys_kill) can be freed while still parked on
     * a wait queue (e.g. blocked in a socket read). Without this, that
     * queue's chain would keep a dangling pointer to freed memory, a
     * use-after-free the next time something wakes it. */
    wait_node_remove(&t->wnode);
    sleepers_cancel(t);
    t->prev->next = t->next;
    t->next->prev = t->prev;
    nthreads--;
    __asm__ volatile("sti");
    kstack_end_check(t);    /* Phase 19.2: teardown is the final chokepoint --
                             * catches a thread that corrupted its stack
                             * bottom and exited before ever switching again */
    if (t->kstack) {                            /* NULL only for the boot thread */
        uint32_t base = (uint32_t)t->kstack;
        for (int i = 0; i < KSTACK_PAGES; i++) {
            uint32_t va = base + (uint32_t)i * PAGE_SIZE;
            uint32_t phys = vmm_get_physical(va);
            vmm_unmap_page(va);
            if (phys)
                pmm_free_frame(phys);
        }
        kstack_slot_free(t->kstack_slot);
    }
    kfree(t);
}

thread_t *thread_current(void)         { return current; }
void  thread_set_proc(thread_t *t, void *p) { t->proc = p; }
void *thread_get_proc(thread_t *t)     { return t->proc; }
void *thread_start_arg(thread_t *t)    { return t->start_arg; }
void  thread_set_pd(thread_t *t, uint32_t pd) { t->pd_phys = pd; }
uint32_t thread_kstack_top(thread_t *t) { return t->kstack_top; }

/* Phase 18.5.6: 1 if `addr` falls in `t`'s guard page (the unmapped page
 * directly below its kstack) -- called from the page-fault handler with
 * the faulting CR2 value to tell a kernel stack overflow apart from any
 * other unmapped-page access. The boot thread (kstack == NULL) has no
 * guard page and never matches. */
int thread_kstack_guard_hit(thread_t *t, uint32_t addr)
{
    if (!t || !t->kstack)
        return 0;
    uint32_t base = (uint32_t)t->kstack;
    return addr >= base - PAGE_SIZE && addr < base;
}

void scheduler_enable(void)  { enabled = 1; }
void scheduler_disable(void) { enabled = 0; }

/* Phase 18.5.6 acceptance-test hook (see SYS_DEBUG_KSTACK_OVERFLOW) --
 * deliberately overflows the CALLING thread's kernel stack so
 * tools/guard_page_qemu.py can confirm the guard page actually catches it.
 * `eat` is written (not just declared) so the compiler can't optimize the
 * frame away, and the recursive call's result feeds into the return value
 * so this can't become a tail call (which -O2 would otherwise turn into a
 * loop that never grows the stack at all). */
static int __attribute__((noinline)) kstack_overflow_recurse(int depth)
{
    volatile uint8_t eat[512];
    for (unsigned i = 0; i < sizeof eat; i++)
        eat[i] = (uint8_t)depth;
    int r = 0;
    if (depth > 0)
        r = kstack_overflow_recurse(depth - 1) + 1;
    return r + eat[0];
}

int sys_debug_kstack_overflow(void)
{
    kprintf("[kernel] debug_kstack_overflow: deliberately overflowing tid=%d's kernel stack\n",
            current->tid);
    kstack_overflow_recurse(1000);   /* 1000 * >=512B frames vs. an 8 KiB stack */
    return 0;   /* unreachable if the guard page works */
}
int  thread_count(void)      { return nthreads; }
