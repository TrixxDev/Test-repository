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
                        /*   OR len|MSG_NOWAIT -> n, or -1 if empty  */
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
#define SYS_MOUSE   28  /* mouse_read(int out[4])    -> 0 (blocks)   */
                        /*   out = {x, y, buttons, absolute}; if     */
                        /*   absolute, x/y are 0..0xFFFF, else deltas*/
#define SYS_READDIR 29  /* readdir(path, index, struct dirent *out)  */
                        /*   -> 1 (filled) / 0 (past end) / -1 (err) */
#define SYS_HALT    30  /* halt() -> no return (root only); powers off */
#define SYS_SYSINFO 31  /* sysinfo(struct sysinfo *out) -> 0/-1         */
#define SYS_SLEEP   32  /* sleep_ms(int ms) -> 0; block the thread ~ms  */
#define SYS_UISCALE 33  /* uiscale(int set) -> current UI scale percent  */
                        /*   set>=100 from root updates it; else reads   */
#define SYS_FBMODE  34  /* fb_set_mode(w, h) -> 1/0 (root only); resize   */
                        /*   the display at runtime (Bochs-VBE path)      */
#define SYS_SHMGET  35  /* shm_create(size, flags) -> id / -1 (shared surface) */
                        /*   flags: SHM_PUBLIC = any process may map it        */
#define SYS_SHMMAP  36  /* shm_map(id) -> user vaddr / 0 (creator/grantee/pub) */
#define SYS_SHMDEL  37  /* shm_destroy(id) -> 0 / -1 (creator only)            */
#define SYS_SHMUNMAP 38 /* shm_unmap(id) -> 0 / -1 (drop this proc's mapping)  */
#define SYS_SHMGRANT 39 /* shm_grant(id, pid) -> 0 / -1 (creator grants map)   */
#define SYS_PERFUS  40  /* perf_us() -> microseconds since boot (low 32 bits),  */
                        /*   a high-resolution monotonic clock (RDTSC-based)    */
#define SYS_NETSTAT 41  /* netstat(struct net_stats *out) -> 0/-1               */
#define SYS_TCPSTAT 42  /* tcpstat(struct tcp_stats *out) -> 0/-1               */
#define SYS_HTTPGET 43  /* http_get(host, buf, cap) -> bytes / <0 (DNS->TCP->GET) */

/* shm_create() flags (arg2). */
#define SHM_PUBLIC  1   /* any process may shm_map the object (e.g. clipboard) */

/* ---- system info (SYS_SYSINFO) ---- */
struct sysinfo {
    unsigned ram_kb;        /* total usable RAM (KiB)            */
    unsigned ram_used_kb;   /* RAM in use (KiB)                  */
    unsigned free_frames;   /* free 4 KiB page frames            */
    unsigned procs;         /* running processes                 */
    unsigned uptime_ms;     /* milliseconds since boot           */
};
/* Note: SYS_REGISTER takes a service mode in arg2 (was reserved/0).   */

/* ---- network interface statistics (SYS_NETSTAT) ---- */
struct net_stats {
    unsigned up;                /* 1 if a NIC is present and DRIVER_OK   */
    unsigned char mac[6];       /* our MAC address                       */
    unsigned char _pad[2];
    unsigned rx_packets, tx_packets;
    unsigned rx_bytes,   tx_bytes;
    unsigned rx_dropped, tx_dropped;  /* frames rejected by bounds checks */
    unsigned rx_errors,  tx_errors;   /* runts/oversize (rx), timeouts (tx) */
    unsigned rx_irqs;           /* device interrupts serviced            */
};

/* ---- TCP statistics (SYS_TCPSTAT) ---- */
struct tcp_stats {
    unsigned connects;      /* tcp_connect() calls            */
    unsigned established;   /* connections reaching ESTABLISHED */
    unsigned resets;        /* RST segments received          */
    unsigned retransmits;   /* (reserved; 0 until Phase 8.4)  */
    unsigned fins;          /* in-order FINs consumed         */
    unsigned drops;         /* segments dropped (csum/match)  */
};

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

/* msgrecv() flag, OR'd into the `len` argument: return -1 immediately instead of
 * blocking when the mailbox is empty. (High bit so it never collides with a real
 * buffer length.) Lets a single-mailbox event loop drain a burst of messages. */
#define MSG_NOWAIT 0x40000000

/* open() flags (passed in arg2): low 2 bits are the access mode */
#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    0x100    /* create the file if it does not exist */
#define O_TRUNC    0x200    /* truncate to zero length on open      */

#define SYS_MAX    44   /* one past the last valid syscall number    */

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
