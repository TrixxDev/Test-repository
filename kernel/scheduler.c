#include "scheduler.h"
#include "kheap.h"
#include "pit.h"
#include "gdt.h"
#include "paging.h"
#include <stdint.h>
#include <stddef.h>

#define STACK_SIZE 8192

enum { TS_READY, TS_BLOCKED, TS_ZOMBIE };

struct thread {
    uint32_t esp;           /* saved kernel stack pointer (must stay first) */
    uint32_t pd_phys;       /* address space (CR3 value) */
    uint32_t kstack_top;    /* ring-0 stack top, loaded into TSS.esp0 */
    void    *kstack;        /* base of the allocated kernel stack */
    int      tid;
    int      state;
    void    *proc;          /* owning process (PCB), or NULL for kernel threads */
    void    *start_arg;     /* argument for trampoline threads */
    uint32_t user_entry;    /* first-run info for user threads */
    uint32_t user_stack;
    struct thread *next;
    struct thread *prev;
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

/* First thing a freshly created user thread runs (in ring 0). */
static void user_thread_start(void)
{
    enter_user_mode(current->user_entry, current->user_stack);
}

void scheduler_init(void)
{
    main_thread.tid        = next_tid++;
    main_thread.pd_phys    = vmm_kernel_directory();
    main_thread.kstack_top = (uint32_t)(main_kstack + sizeof(main_kstack));
    main_thread.kstack     = NULL;
    main_thread.state      = TS_READY;
    main_thread.proc       = NULL;
    main_thread.next       = &main_thread;
    main_thread.prev       = &main_thread;
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
    t->kstack = kmalloc(STACK_SIZE);
    if (!t->kstack) {
        kfree(t);
        return NULL;
    }
    t->tid        = next_tid++;
    t->pd_phys    = pd_phys;
    t->kstack_top = (uint32_t)((uint8_t *)t->kstack + STACK_SIZE);
    t->state      = TS_READY;
    t->proc       = NULL;
    t->start_arg  = NULL;
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

static void do_switch(thread_t *prev, thread_t *next)
{
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

void thread_sleep_ticks(uint32_t nticks)
{
    if (nticks == 0)
        nticks = 1;
    __asm__ volatile("cli");
    int slot = -1;
    for (int i = 0; i < MAX_SLEEPERS; i++)
        if (!sleepers[i].used) { slot = i; break; }
    if (slot < 0) {                 /* table full: degrade to a plain yield */
        __asm__ volatile("sti");
        schedule();
        return;
    }
    sleepers[slot].t    = current;
    sleepers[slot].wake = pit_ticks() + nticks;
    sleepers[slot].used = 1;
    current->state = TS_BLOCKED;
    schedule();                     /* switch away; the tick hook wakes us */
    __asm__ volatile("sti");
}

void thread_zombie_and_yield(void)
{
    __asm__ volatile("cli");
    current->state = TS_ZOMBIE;

    thread_t *prev = current;
    thread_t *next = next_runnable(prev);   /* main thread is always runnable */
    current = next;

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
    t->prev->next = t->next;
    t->next->prev = t->prev;
    nthreads--;
    __asm__ volatile("sti");
    kfree(t->kstack);
    kfree(t);
}

thread_t *thread_current(void)         { return current; }
void  thread_set_proc(thread_t *t, void *p) { t->proc = p; }
void *thread_get_proc(thread_t *t)     { return t->proc; }
void *thread_start_arg(thread_t *t)    { return t->start_arg; }
void  thread_set_pd(thread_t *t, uint32_t pd) { t->pd_phys = pd; }
uint32_t thread_kstack_top(thread_t *t) { return t->kstack_top; }

void scheduler_enable(void)  { enabled = 1; }
void scheduler_disable(void) { enabled = 0; }
int  thread_count(void)      { return nthreads; }
