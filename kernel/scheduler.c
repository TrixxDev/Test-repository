#include "scheduler.h"
#include "kheap.h"
#include "pit.h"
#include <stdint.h>
#include <stddef.h>

#define STACK_SIZE 8192

typedef struct task {
    uint32_t esp;           /* saved stack pointer (must be first) */
    int      id;
    void    *stack;         /* base of the allocated kernel stack */
    struct task *next;
    struct task *prev;
} task_t;

extern void switch_task(uint32_t *old_esp_out, uint32_t new_esp);

static task_t *current;
static task_t  main_task;
static int     next_id;
static int     ntasks;
static volatile int enabled;

void scheduler_init(void)
{
    main_task.id   = next_id++;
    main_task.next = &main_task;
    main_task.prev = &main_task;
    main_task.stack = NULL;
    current = &main_task;
    ntasks = 1;
    pit_set_tick_hook(schedule);
}

int task_create(task_entry_t entry)
{
    task_t *t = (task_t *)kmalloc(sizeof(task_t));
    if (!t)
        return -1;
    t->stack = kmalloc(STACK_SIZE);
    if (!t->stack) {
        kfree(t);
        return -1;
    }
    t->id = next_id++;

    /* Build an initial stack frame that switch_task can "return" into. The
     * layout mirrors switch_task's restore sequence: edi, esi, ebx, ebp,
     * eflags, then the return EIP. We point that at the entry function and put
     * task_exit below it so a returning thread is cleaned up. */
    uint32_t *sp = (uint32_t *)((uint8_t *)t->stack + STACK_SIZE);

    *(--sp) = (uint32_t)task_exit;   /* return address of entry()           */
    *(--sp) = (uint32_t)entry;       /* eip restored by switch_task's ret    */
    *(--sp) = 0x202;                 /* eflags (IF=1) restored by popf        */
    *(--sp) = 0;                     /* ebp                                   */
    *(--sp) = 0;                     /* ebx                                   */
    *(--sp) = 0;                     /* esi                                   */
    *(--sp) = 0;                     /* edi                                   */
    t->esp = (uint32_t)sp;

    /* Insert just before the current task (end of the round-robin cycle). */
    __asm__ volatile("cli");
    t->next = current;
    t->prev = current->prev;
    current->prev->next = t;
    current->prev = t;
    ntasks++;
    __asm__ volatile("sti");

    return t->id;
}

void schedule(void)
{
    if (!enabled || current->next == current)
        return;

    task_t *prev = current;
    current = current->next;
    switch_task(&prev->esp, current->esp);
}

void task_exit(void)
{
    __asm__ volatile("cli");

    task_t *dying = current;
    task_t *next  = current->next;

    /* Unlink the dying task from the ring. */
    dying->prev->next = dying->next;
    dying->next->prev = dying->prev;
    ntasks--;

    current = next;

    /* Switch away for good; the saved esp is discarded. */
    uint32_t discard;
    switch_task(&discard, next->esp);

    /* Not reached. */
    for (;;)
        __asm__ volatile("hlt");
}

void scheduler_enable(void)  { enabled = 1; }
void scheduler_disable(void) { enabled = 0; }
int  task_count(void)        { return ntasks; }
