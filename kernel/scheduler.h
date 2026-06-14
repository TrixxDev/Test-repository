/* Cooperative + preemptive round-robin scheduler for kernel threads. */
#pragma once

typedef void (*task_entry_t)(void);

/* Create the initial task representing the current execution context. */
void scheduler_init(void);

/* Spawn a new kernel thread. Returns its task id, or -1 on failure. */
int task_create(task_entry_t entry);

/* Voluntarily give up the CPU / run the scheduler. */
void schedule(void);

/* Terminate the calling thread; never returns. */
void task_exit(void);

/* Enable preemptive switching from the timer interrupt. */
void scheduler_enable(void);
void scheduler_disable(void);

/* Number of live tasks (including the initial one). */
int task_count(void);
