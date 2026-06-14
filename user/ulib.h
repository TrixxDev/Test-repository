/* Minimal user-space library for AuroraOS programs (ring 3, int 0x80). */
#pragma once

#define SYS_PUTC   1
#define SYS_YIELD  2
#define SYS_EXIT   3
#define SYS_FORK   4
#define SYS_EXEC   5
#define SYS_WAIT   6
#define SYS_OPEN   7
#define SYS_READ   8
#define SYS_WRITE  9
#define SYS_CLOSE  10
#define SYS_GETPID 11

static inline int _syscall(int n, int a, int b, int c)
{
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "b"(a), "c"(b), "d"(c)
                     : "memory");
    return ret;
}

static inline int  sys_write(int fd, const char *buf, int len) { return _syscall(SYS_WRITE, fd, (int)buf, len); }
static inline int  sys_read(int fd, char *buf, int len)        { return _syscall(SYS_READ, fd, (int)buf, len); }
static inline int  sys_open(const char *path, int flags)       { return _syscall(SYS_OPEN, (int)path, flags, 0); }
static inline int  sys_close(int fd)                           { return _syscall(SYS_CLOSE, fd, 0, 0); }
static inline int  sys_fork(void)                              { return _syscall(SYS_FORK, 0, 0, 0); }
static inline int  sys_exec(const char *path)                  { return _syscall(SYS_EXEC, (int)path, 0, 0); }
static inline int  sys_wait(int *status)                       { return _syscall(SYS_WAIT, -1, (int)status, 0); }
static inline int  sys_getpid(void)                            { return _syscall(SYS_GETPID, 0, 0, 0); }
static inline void sys_exit(int code)                          { _syscall(SYS_EXIT, code, 0, 0); }

static inline int ustrlen(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

static inline void uputs(const char *s)
{
    sys_write(1, s, ustrlen(s));
}

/* Print "label = value\n" using only write(). */
static inline void uputint(const char *label, int v)
{
    char digits[12];
    char out[96];
    int p = 0;

    while (*label)
        out[p++] = *label++;
    out[p++] = ' ';
    out[p++] = '=';
    out[p++] = ' ';

    int neg = v < 0;
    unsigned int x = neg ? (unsigned int)(-v) : (unsigned int)v;
    int d = 0;
    if (x == 0)
        digits[d++] = '0';
    while (x) {
        digits[d++] = (char)('0' + x % 10);
        x /= 10;
    }
    if (neg)
        out[p++] = '-';
    while (d)
        out[p++] = digits[--d];
    out[p++] = '\n';

    sys_write(1, out, p);
}
