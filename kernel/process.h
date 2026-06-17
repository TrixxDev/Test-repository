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
#include "syscall_abi.h"

#define MAX_FDS   16
#define MSG_MAX   256

enum proc_state { PROC_UNUSED = 0, PROC_RUNNING, PROC_ZOMBIE };

/* A queued IPC message. */
typedef struct message {
    struct message *next;
    int  from;
    int  len;
    char data[MSG_MAX];
} message_t;

enum fd_role { FD_NORMAL = 0, FD_PIPE_R, FD_PIPE_W, FD_SOCKET };

typedef struct file {
    vfs_node_t *node;
    uint32_t    offset;
    int         refcount;
    int         role;       /* FD_NORMAL / FD_PIPE_R / FD_PIPE_W */
} file_t;

typedef struct process {
    int      pid;
    int      ppid;
    int      uid;                   /* owner: 0 = root (kernel/init/services) */
    uint32_t pd_phys;               /* address space */
    int      state;
    int      exit_code;
    file_t  *fds[MAX_FDS];          /* descriptor table */
    struct thread  *thread;         /* the (single) thread */
    struct process *parent;
    registers_t saved_regs;         /* fork: child resumes from this frame */
    int      waiting;               /* parent is blocked in wait() */
    uint32_t user_brk;              /* top of the user heap (sbrk) */

    /* message-passing mailbox */
    message_t *mbox_head, *mbox_tail;
    int        mbox_count;
    struct thread *mbox_waiter;     /* thread blocked in recv() */
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
int  process_wait(int pid, int *status_user, int nohang);
int  sys_kill(int pid);

int  sys_open(const char *path, int flags);
int  sys_read(int fd, void *buf, uint32_t len);
int  sys_write(int fd, const void *buf, uint32_t len);
int  sys_close(int fd);
int  sys_readdir(const char *path, int index, struct dirent *out);
int  sys_sysinfo(struct sysinfo *out);
int  sys_sleep(int ms);
int  process_count(void);
int  sys_pipe(int fds[2]);
int  sys_dup2(int oldfd, int newfd);
uint32_t sys_sbrk(int increment);

/* message-passing IPC + named service registry */
int  sys_msgsend(int pid, const void *buf, int len);
int  sys_msgrecv(void *buf, int len, int *from);
int  sys_register(const char *name, uint32_t mode);
int  sys_lookup(const char *name);

/* sockets (loopback) + poll */
int  sys_socket(int domain, int type);
int  sys_poll(struct pollfd *fds, int nfds, int timeout);
int  sys_getuid(void);
int  sys_setuid(int uid);
int  sys_uid_of(int pid);

/* Resolve a (pid, fd) to its socket VFS node, or NULL if it is not a socket
 * descriptor in that process. Used by the netd broker via sock_link(). */
vfs_node_t *proc_socket_node(int pid, int fd);
