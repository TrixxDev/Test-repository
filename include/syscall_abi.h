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
#define SYS_INET_CONNECT 44 /* inet_connect(fd, host, port) -> 0/-2 DNS/-3 (AF_INET) */
#define SYS_FCNTL   45  /* fcntl(fd, cmd, arg) -> see F_GETFL/F_SETFL below         */

/* ---- Phase 18.2: unified kernel error codes ----
 * Existing syscalls that predate this still just return a generic -1 on
 * failure; that's unchanged. These are specific, small negative values a
 * caller can compare against by name when it needs to react differently to
 * a particular reason, the same way real errno values work -- but returned
 * directly as the syscall's own value (there is no separate errno variable
 * here), matching this ABI's existing "negative on error" convention. */
#define EAGAIN      11  /* a non-blocking operation would have to wait     */
#define EWOULDBLOCK EAGAIN  /* POSIX historically distinguishes these; Aurora, like Linux, does not */
#define EINTR       4   /* a blocking wait was interrupted before completing.
                          * Defined for completeness (the error-code model
                          * every subsystem shares should name it), but
                          * nothing returns it yet: Aurora has no signal
                          * mechanism to interrupt a blocking wait. It
                          * becomes real once one exists. */

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
    unsigned max_inflight;  /* Phase 18.4.1: highest number of unacknowledged
                              * segments any one connection has had queued at
                              * once, lifetime max across all connections --
                              * >1 is direct proof sends were pipelined, not
                              * stop-and-wait */
    unsigned ooo_segments;  /* Phase 18.4.2: out-of-order segments buffered
                              * (later spliced into the in-order stream once
                              * the gap before them closed), instead of being
                              * dropped for the peer to blindly retransmit */
};

/* ---- Phase 18.5.2: kernel-wide profiling counters (SYS_PROFSTAT) ----
 * A first, deliberately small slice of "where does the CPU actually go":
 * scheduling activity, TCP's two hot entry points, FAT32's two hot entry
 * points, and bulk memory copies. Each _us field is a cumulative count of
 * microseconds (perf_now_us(), the same RDTSC-based clock the compositor
 * already profiles itself with), not a snapshot -- divide by the matching
 * _calls field for an average. Userspace/TLS/HTTP2/GUI timing is out of
 * scope here: those run inside separate userspace processes with their own
 * address spaces, so they need their own in-process accounting rather than
 * a shared kernel struct -- a deliberate scope cut, not an oversight. */
struct kernel_prof {
    unsigned sched_switches;   /* real context switches (do_switch() calls) --
                                 * excludes schedule() calls that found nothing
                                 * else runnable and returned without swapping */
    unsigned wait_blocks;      /* times a thread actually blocked on a wait
                                 * queue (or a wait queue + timeout), instead of
                                 * finding what it needed already ready */
    unsigned tcp_input_calls;
    unsigned tcp_input_us;
    unsigned tcp_tick_calls;
    unsigned tcp_tick_us;
    unsigned fat_read_calls;
    unsigned fat_read_us;
    unsigned fat_write_calls;
    unsigned fat_write_us;
    unsigned memcpy_calls;
    unsigned memcpy_bytes;

    /* Phase 18.5.4: tcpsock's tsk_read() loop specifically (net/tcpsock.c) --
     * added to find out WHY tcp_tick_calls (driven by net_poll(), which
     * tsk_read()'s loop calls once per pass) can run orders of magnitude
     * higher for one workload than another at the same wall-clock duration.
     * tcp_read_calls is syscall-level (one per read() reaching this fd);
     * tcp_read_iters is loop-level (one per net_poll() pass inside a single
     * read(), so tcp_read_iters/tcp_read_calls is the average number of
     * "still no data" retries per read()); tcp_read_bytes is bytes actually
     * returned on the successful passes. tcp_wait_us times only the
     * wait_event_timeout() calls this same loop makes -- dividing by the
     * (shared, pre-existing) wait_blocks counter gives the average real
     * wait duration per block, which is the direct answer to "is this loop
     * actually sleeping ~20ms, or basically not sleeping at all." */
    unsigned tcp_read_calls;
    unsigned tcp_read_iters;
    unsigned tcp_read_bytes;
    unsigned tcp_wait_us;

    /* Phase 18.5.4 continued: tcp_read_iters alone turned out NOT to explain
     * a huge tcp_tick_calls gap between two workloads at the same wall-clock
     * duration (9 read-loop iterations either way) -- so net_poll()'s other
     * three tcpsock.c call sites (the connect wait, the write-side
     * wait-for-ACK-before-next-chunk loop, and the close teardown wait) each
     * get their own iteration counter too, to find out which phase actually
     * accounts for the difference instead of guessing. */
    unsigned tcp_connect_iters;
    unsigned tcp_write_iters;
    unsigned tcp_close_iters;
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
#define O_NONBLOCK 0x400    /* Phase 18.2: read()/write() return -EAGAIN
                              * instead of blocking when the operation isn't
                              * immediately possible. Settable at open() time
                              * or later via fcntl(fd, F_SETFL, O_NONBLOCK) --
                              * the latter is how a pipe or socket fd (never
                              * created through open()) gets it. */

/* fcntl() commands (arg2); arg3 is the command's own argument.
 * F_SETFL only ever affects O_NONBLOCK here -- there is no O_APPEND or
 * other settable status flag yet, so other bits in `arg` are ignored. */
#define F_GETFL    1    /* -> this fd's current flags word           */
#define F_SETFL    2    /* set flags (arg3 & O_NONBLOCK) -> 0        */

#define SYS_WAIT_EVENTS 46  /* wait_events(pollfd*, nfds, timeout_ms) -> nready / -1 */
                        /* Phase 18.3: like poll() (SYS_POLL, below) but covers    */
                        /* every fd role -- console, pipe, loopback socket, TCP    */
                        /* socket -- not just loopback sockets, and honors         */
                        /* timeout_ms as a real bound: negative waits forever, 0   */
                        /* never blocks, >0 is milliseconds. A separate syscall    */
                        /* from SYS_POLL so no existing caller's behavior changes. */

#define SYS_PROFSTAT 47 /* profstat(struct kernel_prof *out) -> 0/-1 (Phase 18.5.2) */

#define SYS_MAX    48   /* one past the last valid syscall number    */

/* ---- socket layer ---- */
#define AF_LOOPBACK  1  /* in-machine sockets brokered by netd       */
#define AF_INET      2  /* IPv4 stream sockets over the TCP stack    */
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
