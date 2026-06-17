/* AuroraOS system call ABI — the single source of truth shared by the kernel
 * and user space. Do not renumber existing calls; only append new ones.
 *
 * Calling convention (int 0x80):
 *   eax = syscall number
 *   ebx = arg1, ecx = arg2, edx = arg3
 *   eax = return value (negative on error)
 */
#pragma once

#define SYS_PUTC   1    /* putc(char c)                              */
#define SYS_YIELD  2    /* yield()                                   */
#define SYS_EXIT   3    /* exit(int code)            -> no return    */
#define SYS_FORK   4    /* fork()                    -> pid / 0       */
#define SYS_EXEC   5    /* exec(const char *path, char **argv)       */
#define SYS_WAIT   6    /* wait(int *status)         -> pid          */
#define SYS_OPEN   7    /* open(const char *path, int flags) -> fd   */
#define SYS_READ   8    /* read(int fd, void *buf, uint len) -> n    */
#define SYS_WRITE  9    /* write(int fd, const void *buf, uint len)  */
#define SYS_CLOSE  10   /* close(int fd)                             */
#define SYS_GETPID 11   /* getpid() -> pid                           */
#define SYS_PIPE   12   /* pipe(int fd[2])           -> 0 / -1       */
#define SYS_DUP2   13   /* dup2(int oldfd, int newfd)-> newfd        */
#define SYS_SBRK   14   /* sbrk(int incr)            -> old brk      */
#define SYS_MSGSEND 15  /* msgsend(pid, buf, len)    -> 0 / -1       */
#define SYS_MSGRECV 16  /* msgrecv(buf, len, &from)  -> n (blocks)   */
#define SYS_REGISTER 17 /* register(name)            -> 0 / -1       */
#define SYS_LOOKUP  18  /* lookup(name)              -> pid / -1     */
#define SYS_KILL    19  /* kill(pid)                 -> 0 / -1       */
#define SYS_SOCKET  20  /* socket(domain, type)      -> fd / -1      */
#define SYS_SOCK_LINK 21/* sock_link(handle_a, handle_b) -> 0 / -1   */
#define SYS_POLL    22  /* poll(pollfd*, nfds, tmo)  -> nready / -1  */
#define SYS_GETUID  23  /* getuid()                  -> uid          */
#define SYS_SETUID  24  /* setuid(uid)               -> 0 / -1       */
#define SYS_UIDOF   25  /* uid_of(pid)               -> uid / -1     */
#define SYS_FBMAP   26  /* fb_map(uint info[3])      -> user vaddr/0 */
#define SYS_FBACTIVE 27 /* fb_active()               -> 1 / 0        */
#define SYS_MOUSE   28  /* mouse_read(int out[3])    -> 0 (blocks)   */
                        /*   out = {dx, dy, buttons}                 */
#define SYS_READDIR 29  /* readdir(path, index, struct dirent *out)  */
                        /*   -> 1 (filled) / 0 (past end) / -1 (err) */
#define SYS_HALT    30  /* halt() -> no return (root only); powers off */
/* Note: SYS_REGISTER takes a service mode in arg2 (was reserved/0).   */

/* ---- directory enumeration (SYS_READDIR) ---- */
#define DT_FILE 1       /* a regular file      */
#define DT_DIR  2       /* a directory         */

struct dirent {
    char     name[64];  /* entry name (NUL-terminated)               */
    unsigned type;      /* DT_FILE / DT_DIR                          */
    unsigned size;      /* size in bytes (files)                     */
};

/* wait() flags (passed in arg2) */
#define WNOHANG    1    /* return 0 immediately if no child has exited */

/* open() flags (passed in arg2): low 2 bits are the access mode */
#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    0x100    /* create the file if it does not exist */
#define O_TRUNC    0x200    /* truncate to zero length on open      */

#define SYS_MAX    31   /* one past the last valid syscall number    */

/* ---- socket layer (AF_LOOPBACK only for now) ---- */
#define AF_LOOPBACK  1  /* in-machine sockets brokered by netd       */
#define SOCK_STREAM  1  /* reliable, ordered byte stream             */

/* A kernel socket is named across processes by a packed (pid, fd) handle so the
 * netd broker can join two endpoints with sock_link(). fds are small, so 16
 * bits each is ample. */
#define SOCK_HANDLE(pid, fd) (((pid) << 16) | ((fd) & 0xFFFF))
#define SOCK_HANDLE_PID(h)   (((h) >> 16) & 0xFFFF)
#define SOCK_HANDLE_FD(h)    ((h) & 0xFFFF)

/* poll() event/return bits and descriptor record (ABI: shared kernel+user). */
#define POLLIN   0x01   /* readable without blocking (data or EOF)   */
#define POLLOUT  0x04   /* writable without blocking                 */
#define POLLERR  0x08   /* error / peer gone                         */

struct pollfd {
    int   fd;
    short events;       /* requested: POLLIN | POLLOUT               */
    short revents;      /* returned: ready bits                      */
};
