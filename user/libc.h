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
static inline int   getpid(void)                        { return _syscall(SYS_GETPID, 0, 0, 0); }
static inline void  _exit(int c)                        { _syscall(SYS_EXIT, c, 0, 0); }
static inline int   pipe(int fd[2])                     { return _syscall(SYS_PIPE, (int)fd, 0, 0); }
static inline int   dup2(int o, int n)                  { return _syscall(SYS_DUP2, o, n, 0); }
static inline void *sbrk(int incr)                      { return (void *)_syscall(SYS_SBRK, incr, 0, 0); }

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
