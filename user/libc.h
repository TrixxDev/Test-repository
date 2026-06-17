/* AuroraOS mini libc — a small, stable userspace API.
 *
 * Programs define `int main(int argc, char **argv)`; crt0 calls it and exits
 * with the return value. System calls follow include/syscall_abi.h. */
#pragma once
#include "syscall_abi.h"
#include <stddef.h>
#include <stdarg.h>

/* ---- raw system call wrappers ---- */
static inline int _syscall(int n, int a, int b, int c)
{
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
    return ret;
}

static inline int   write(int fd, const void *b, int n) { return _syscall(SYS_WRITE, fd, (int)b, n); }
static inline int   read(int fd, void *b, int n)        { return _syscall(SYS_READ, fd, (int)b, n); }
static inline int   open(const char *p, int f)          { return _syscall(SYS_OPEN, (int)p, f, 0); }
static inline int   close(int fd)                       { return _syscall(SYS_CLOSE, fd, 0, 0); }
static inline int   fork(void)                          { return _syscall(SYS_FORK, 0, 0, 0); }
static inline int   execv(const char *p, char **argv)   { return _syscall(SYS_EXEC, (int)p, (int)argv, 0); }
static inline int   wait(int *status)                   { return _syscall(SYS_WAIT, (int)status, 0, 0); }
static inline int   wait_nohang(int *status)            { return _syscall(SYS_WAIT, (int)status, WNOHANG, 0); }
static inline int   kill(int pid)                       { return _syscall(SYS_KILL, pid, 0, 0); }
static inline int   getpid(void)                        { return _syscall(SYS_GETPID, 0, 0, 0); }
static inline void  _exit(int c)                        { _syscall(SYS_EXIT, c, 0, 0); }
static inline int   pipe(int fd[2])                     { return _syscall(SYS_PIPE, (int)fd, 0, 0); }
static inline int   dup2(int o, int n)                  { return _syscall(SYS_DUP2, o, n, 0); }
static inline void *sbrk(int incr)                      { return (void *)_syscall(SYS_SBRK, incr, 0, 0); }

/* message-passing IPC + named services */
static inline int msgsend(int pid, const void *b, int n) { return _syscall(SYS_MSGSEND, pid, (int)b, n); }
static inline int msgrecv(void *b, int n, int *from)     { return _syscall(SYS_MSGRECV, (int)b, n, (int)from); }
/* Non-blocking receive: returns n (>=0) if a message was dequeued, or -1 if the
 * mailbox was empty (would block). Lets an event loop drain a burst of events. */
static inline int msgrecv_nb(void *b, int n, int *from)  { return _syscall(SYS_MSGRECV, (int)b, n | MSG_NOWAIT, (int)from); }
/* svc_register defaults to a world-discoverable service (0644); use
 * svc_register_mode for a private one (e.g. 0600 = root-only lookup). */
static inline int svc_register_mode(const char *name, int mode) { return _syscall(SYS_REGISTER, (int)name, mode, 0); }
static inline int svc_register(const char *name)         { return _syscall(SYS_REGISTER, (int)name, 0644, 0); }
static inline int svc_lookup(const char *name)           { return _syscall(SYS_LOOKUP, (int)name, 0, 0); }

/* sockets (loopback) + poll + uid */
static inline int socket(int domain, int type)           { return _syscall(SYS_SOCKET, domain, type, 0); }
static inline int sock_link(int handle_a, int handle_b)  { return _syscall(SYS_SOCK_LINK, handle_a, handle_b, 0); }
static inline int poll(struct pollfd *fds, int nfds, int timeout) { return _syscall(SYS_POLL, (int)fds, nfds, timeout); }
static inline int getuid(void)                           { return _syscall(SYS_GETUID, 0, 0, 0); }
static inline int setuid(int uid)                        { return _syscall(SYS_SETUID, uid, 0, 0); }
static inline int uid_of(int pid)                        { return _syscall(SYS_UIDOF, pid, 0, 0); }
/* Map the framebuffer into this process; fills info[0..2] = {w,h,pitch}. */
static inline void *fb_map(unsigned *info)               { return (void *)_syscall(SYS_FBMAP, (int)info, 0, 0); }
static inline int   fb_active(void)                      { return _syscall(SYS_FBACTIVE, 0, 0, 0); }
/* Block for one pointer event; fills info[0..2] = {dx, dy, buttons}. */
static inline int   mouse_read(int *info)                { return _syscall(SYS_MOUSE, (int)info, 0, 0); }
/* Read directory `path` entry `index` into *out: 1 = filled, 0 = past end, -1 err. */
static inline int   readdir(const char *path, int index, struct dirent *out) { return _syscall(SYS_READDIR, (int)path, index, (int)out); }
/* Power off the machine (root only; no return on success). */
static inline int   halt(void)                          { return _syscall(SYS_HALT, 0, 0, 0); }
/* Fill *out with RAM/process/uptime stats. Returns 0/-1. */
static inline int   sysinfo(struct sysinfo *out)        { return _syscall(SYS_SYSINFO, (int)out, 0, 0); }

/* send/recv are just write/read on a connected socket fd. */
static inline int send(int fd, const void *b, int n)     { return write(fd, b, n); }
static inline int recv(int fd, void *b, int n)           { return read(fd, b, n); }

/* netd-brokered connection setup (user/libc/net.c). */
int bind(int fd, int port);
int listen(int fd);
int connect(int fd, int port);
int accept(int port);

/* ---- string.c ---- */
size_t strlen(const char *s);
int    strcmp(const char *a, const char *b);
int    strncmp(const char *a, const char *b, size_t n);
char  *strcpy(char *dst, const char *src);
void  *memcpy(void *dst, const void *src, size_t n);
void  *memset(void *dst, int c, size_t n);
void  *memmove(void *dst, const void *src, size_t n);

/* ---- stdio.c (printf.c) ---- */
int    printf(const char *fmt, ...);
int    fprintf(int fd, const char *fmt, ...);
int    puts(const char *s);
int    putchar(int c);

/* ---- malloc.c ---- */
void  *malloc(size_t size);
void   free(void *ptr);
