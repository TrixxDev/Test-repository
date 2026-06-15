/* Process model v3: a Unix-like process control block.
 *
 *   process = address space (page directory)
 *           + file descriptor table
 *           + lifecycle state + exit code
 *           + a thread of execution
 */
#pragma once
#include <stdint.h>
#include "isr.h"
#include "vfs.h"

#define MAX_FDS   16

enum proc_state { PROC_UNUSED = 0, PROC_RUNNING, PROC_ZOMBIE };

enum fd_role { FD_NORMAL = 0, FD_PIPE_R, FD_PIPE_W };

typedef struct file {
    vfs_node_t *node;
    uint32_t    offset;
    int         refcount;
    int         role;       /* FD_NORMAL / FD_PIPE_R / FD_PIPE_W */
} file_t;

typedef struct process {
    int      pid;
    int      ppid;
    uint32_t pd_phys;               /* address space */
    int      state;
    int      exit_code;
    file_t  *fds[MAX_FDS];          /* descriptor table */
    struct thread  *thread;         /* the (single) thread */
    struct process *parent;
    registers_t saved_regs;         /* fork: child resumes from this frame */
    int      waiting;               /* parent is blocked in wait() */
    uint32_t user_brk;              /* top of the user heap (sbrk) */
} process_t;

/* Set up the kernel process (pid 0) bound to the current/main thread. */
void process_init(void);

/* The process owning the currently running thread. */
process_t *process_current(void);

/* Create a process from an ELF image and start it in ring 3. `name` becomes
 * argv[0]. Returns pid. */
int process_spawn(const uint8_t *elf, uint32_t size, const char *name);

/* System-call backends (operate on the current process). */
int  do_fork(registers_t *regs);
void do_exec(const char *path, char **argv, registers_t *regs); /* no return on success */
void process_exit(int code);                          /* never returns */
int  process_wait(int pid, int *status_user);

int  sys_open(const char *path, int flags);
int  sys_read(int fd, void *buf, uint32_t len);
int  sys_write(int fd, const void *buf, uint32_t len);
int  sys_close(int fd);
int  sys_pipe(int fds[2]);
int  sys_dup2(int oldfd, int newfd);
uint32_t sys_sbrk(int increment);
