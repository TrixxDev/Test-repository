#include "process.h"
#include "paging.h"
#include "pmm.h"
#include "pit.h"
#include "elf.h"
#include "scheduler.h"
#include "kheap.h"
#include "string.h"
#include "kio.h"
#include "console.h"
#include "pipe.h"
#include "socket.h"
#include "uaccess.h"
#include "shm.h"
#include "virtio_net.h"
#include "tcp.h"

#define MAX_PROCS    32
#define USTACK_TOP   0xC0000000u
#define USTACK_PAGES 4
#define USER_HEAP_BASE 0x50000000u

#define USER_CODE 0x1B
#define USER_DATA 0x23

#define MAX_ARG  16
#define ARG_LEN  64

static process_t proc_table[MAX_PROCS];
static int next_pid;

static process_t *alloc_proc(void)
{
    for (int i = 0; i < MAX_PROCS; i++) {
        if (proc_table[i].state == PROC_UNUSED) {
            process_t *p = &proc_table[i];
            memset(p, 0, sizeof(*p));
            p->pid = next_pid++;
            p->state = PROC_RUNNING;
            return p;
        }
    }
    return NULL;
}

process_t *process_current(void)
{
    return (process_t *)thread_get_proc(thread_current());
}

/* ---- file descriptors ---- */

/* Drop one reference to an open file; on the last reference, release any pipe
 * end it represents and free it. */
static void file_unref(file_t *f)
{
    if (!f)
        return;
    if (--f->refcount == 0) {
        if (f->role == FD_PIPE_R)
            pipe_close_end(f->node, 0);
        else if (f->role == FD_PIPE_W)
            pipe_close_end(f->node, 1);
        else if (f->role == FD_SOCKET)
            sock_close(f->node);
        kfree(f);
    }
}

static int fd_install_role(process_t *p, vfs_node_t *node, int role)
{
    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (!p->fds[fd]) {
            file_t *f = (file_t *)kmalloc(sizeof(file_t));
            if (!f)
                return -1;
            f->node = node;
            f->offset = 0;
            f->refcount = 1;
            f->role = role;
            /* Default access by role; sys_open refines a regular file to its
             * open mode (O_RDONLY/WRONLY/RDWR). */
            f->access = (role == FD_PIPE_R) ? VFS_R
                      : (role == FD_PIPE_W) ? VFS_W
                      : (VFS_R | VFS_W);    /* FD_SOCKET, FD_NORMAL */
            p->fds[fd] = f;
            return fd;
        }
    }
    return -1;
}

static int fd_install(process_t *p, vfs_node_t *node)
{
    return fd_install_role(p, node, FD_NORMAL);
}

static void open_standard_streams(process_t *p)
{
    vfs_node_t *con = console_node();
    for (int fd = 0; fd < 3; fd++) {
        file_t *f = (file_t *)kmalloc(sizeof(file_t));
        f->node = con;
        f->offset = 0;
        f->refcount = 1;
        f->role = FD_NORMAL;
        f->access = VFS_R | VFS_W;       /* console is readable + writable */
        p->fds[fd] = f;
    }
}

static void close_all_fds(process_t *p)
{
    for (int fd = 0; fd < MAX_FDS; fd++) {
        file_unref(p->fds[fd]);
        p->fds[fd] = NULL;
    }
}

/* Create `path`'s file in its parent directory (used for O_CREAT). Requires
 * write permission on the parent. Returns the new node, owned by the caller. */
static vfs_node_t *create_file(const char *path, int uid)
{
    int len = 0;
    while (path[len] && len < 255) len++;
    int slash = -1;
    for (int i = 0; i < len; i++)
        if (path[i] == '/') slash = i;
    if (slash < 0)
        return NULL;

    char dir[128], base[64];
    int di = 0;
    if (slash == 0) {
        dir[di++] = '/';
    } else {
        for (int i = 0; i < slash && di < 127; i++) dir[di++] = path[i];
    }
    dir[di] = '\0';
    int bi = 0;
    for (int i = slash + 1; i < len && bi < 63; i++) base[bi++] = path[i];
    base[bi] = '\0';
    if (base[0] == '\0')
        return NULL;

    vfs_node_t *d = vfs_resolve(dir);
    if (!d || !vfs_permitted(d, uid, VFS_W))
        return NULL;

    vfs_node_t *node = vfs_create(d, base, VFS_FILE);
    if (node) {
        node->owner_uid = uid;
        node->mode = 0644;
    }
    return node;
}

int process_count(void)
{
    int n = 0;
    for (int i = 0; i < MAX_PROCS; i++)
        if (proc_table[i].state == PROC_RUNNING)
            n++;
    return n;
}

int sys_sysinfo(struct sysinfo *out)
{
    if (!is_user_addr((uint32_t)out, sizeof(*out)))
        return -1;
    struct sysinfo si;
    si.ram_kb      = pmm_total_frames() * 4;
    si.ram_used_kb = pmm_used_frames()  * 4;
    si.free_frames = pmm_free_frames();
    si.procs       = (unsigned)process_count();
    si.uptime_ms   = pit_ticks() * 10;          /* PIT runs at 100 Hz */
    memcpy(out, &si, sizeof(si));
    return 0;
}

/* Copy the network interface counters out to user space. */
int sys_netstat(struct net_stats *out)
{
    if (!is_user_addr((uint32_t)out, sizeof(*out)))
        return -1;
    struct net_stats ns;
    net_get_stats(&ns);
    memcpy(out, &ns, sizeof(ns));
    return 0;
}

/* Copy the TCP counters out to user space. */
int sys_tcpstat(struct tcp_stats *out)
{
    if (!is_user_addr((uint32_t)out, sizeof(*out)))
        return -1;
    struct tcp_stats ts;
    tcp_get_stats(&ts);
    memcpy(out, &ts, sizeof(ts));
    return 0;
}

/* Block the calling thread for ~`ms` milliseconds (PIT runs at 100 Hz -> 10 ms
 * per tick). Used by the window server's render ticker for a fixed cadence. */
int sys_sleep(int ms)
{
    if (ms <= 0)
        return 0;
    thread_sleep_ticks((uint32_t)(ms / 10));    /* thread_sleep_ticks floors to 1 */
    return 0;
}

/* Canonical UI scale (percent, 100..200). The window server (root) publishes the
 * user's choice here; ordinary apps read it so they can lay out their content to
 * match the scaled chrome. `set` >= 100 from root updates it; any other call (or a
 * non-root caller) just reads the current value. */
static int g_ui_scale = 100;
int sys_uiscale(int set)
{
    if (set >= 100 && process_current()->uid == 0) {
        if (set > 200) set = 200;
        g_ui_scale = set;
    }
    return g_ui_scale;
}

int sys_open(const char *path, int flags)
{
    char kpath[256];
    int path_len = copy_str_from_user(kpath, path, sizeof(kpath));
    if (path_len < 0) {
        kprintf("[syscall] sys_open: invalid user path pointer 0x%x\n", (uint32_t)path);
        return -1;
    }
    
    int uid = process_current()->uid;
    vfs_node_t *node = vfs_resolve(kpath);

    if (!node) {
        if (!(flags & O_CREAT))
            return -1;
        node = create_file(kpath, uid);
        if (!node)
            return -1;
    }

    int want = VFS_R;
    int acc = flags & 3;
    if (acc == O_WRONLY)      want = VFS_W;
    else if (acc == O_RDWR)   want = VFS_R | VFS_W;
    if (!vfs_permitted(node, uid, want))
        return -1;

    if (flags & O_TRUNC)
        node->size = 0;     /* logical truncate; the next write persists it */

    int fd = fd_install(process_current(), node);
    if (fd >= 0)
        process_current()->fds[fd]->access = want;  /* enforce the open mode */
    return fd;
}

/* Enumerate one directory entry. Returns 1 if *out was filled, 0 past the last
 * entry, -1 on error (bad path, not a directory, or no read permission). The
 * Finder uses this the same way the shell uses open/read — no special rights. */
int sys_readdir(const char *path, int index, struct dirent *out)
{
    char kpath[256];
    if (copy_str_from_user(kpath, path, sizeof(kpath)) < 0)
        return -1;
    if (!is_user_addr((uint32_t)out, sizeof(*out)))
        return -1;

    vfs_node_t *dir = vfs_resolve(kpath);
    if (!dir || !(dir->flags & VFS_DIR))
        return -1;
    if (!vfs_permitted(dir, process_current()->uid, VFS_R))
        return -1;

    char name[64];
    if (vfs_readdir(dir, (uint32_t)index, name, sizeof(name)) != 0)
        return 0;                           /* past the last entry */

    struct dirent d;
    memset(&d, 0, sizeof(d));
    int i = 0;
    while (name[i] && i < (int)sizeof(d.name) - 1) { d.name[i] = name[i]; i++; }
    d.name[i] = '\0';

    vfs_node_t *child = vfs_finddir(dir, name);
    if (child) {
        d.type = (child->flags & VFS_DIR) ? DT_DIR : DT_FILE;
        d.size = child->size;
    } else {
        d.type = DT_FILE;                   /* shouldn't happen; be safe */
        d.size = 0;
    }

    memcpy(out, &d, sizeof(d));             /* user pointer already validated */
    return 1;
}

int sys_read(int fd, void *buf, uint32_t len)
{
    process_t *p = process_current();
    if (fd < 0 || fd >= MAX_FDS || !p->fds[fd])
        return -1;
    file_t *f = p->fds[fd];
    if (!(f->access & VFS_R))               /* fd not opened for reading */
        return -1;
    if (len && !is_user_addr((uint32_t)buf, len)) {
        kprintf("[syscall] sys_read: invalid user buffer 0x%x (len=%u)\n", (uint32_t)buf, len);
        return -1;
    }
    int n = vfs_read(f->node, f->offset, len, (uint8_t *)buf);
    if (n > 0)
        f->offset += (uint32_t)n;
    return n;
}

int sys_write(int fd, const void *buf, uint32_t len)
{
    process_t *p = process_current();
    if (fd < 0 || fd >= MAX_FDS || !p->fds[fd])
        return -1;
    file_t *f = p->fds[fd];
    if (!(f->access & VFS_W))               /* fd not opened for writing */
        return -1;

    /* Validate user buffer pointer before copying */
    if (len && !is_user_addr((uint32_t)buf, len)) {
        kprintf("[syscall] sys_write: invalid user buffer 0x%x (len=%u)\n", (uint32_t)buf, len);
        return -1;
    }
    int n = vfs_write(f->node, f->offset, len, (const uint8_t *)buf);
    if (n > 0)
        f->offset += (uint32_t)n;
    return n;
}

int sys_close(int fd)
{
    process_t *p = process_current();
    if (fd < 0 || fd >= MAX_FDS || !p->fds[fd])
        return -1;
    file_unref(p->fds[fd]);
    p->fds[fd] = NULL;
    return 0;
}

int sys_pipe(int fds[2])
{
    process_t *p = process_current();
    vfs_node_t *rnode, *wnode;
    if (pipe_create(&rnode, &wnode) != 0)
        return -1;

    int rfd = fd_install_role(p, rnode, FD_PIPE_R);
    int wfd = fd_install_role(p, wnode, FD_PIPE_W);
    if (rfd < 0 || wfd < 0)
        return -1;

    fds[0] = rfd;
    fds[1] = wfd;
    return 0;
}

int sys_dup2(int oldfd, int newfd)
{
    process_t *p = process_current();
    if (oldfd < 0 || oldfd >= MAX_FDS || !p->fds[oldfd])
        return -1;
    if (newfd < 0 || newfd >= MAX_FDS)
        return -1;
    if (oldfd == newfd)
        return newfd;

    if (p->fds[newfd])
        file_unref(p->fds[newfd]);

    p->fds[newfd] = p->fds[oldfd];
    p->fds[newfd]->refcount++;
    return newfd;
}

uint32_t sys_sbrk(int increment)
{
    process_t *p = process_current();
    uint32_t old = p->user_brk;
    uint32_t neu = old + (uint32_t)increment;

    if (increment > 0) {
        uint32_t a = old & ~0xFFFu;
        while (a < neu) {
            if (vmm_get_physical(a) == 0)
                vmm_map_page(a, pmm_alloc_frame(),
                             PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
            a += 0x1000;
        }
    }
    p->user_brk = neu;
    return old;
}

/* ---- message-passing IPC + named services ---- */

#define MAX_SERVICES 16
#define MBOX_LIMIT   64

static struct {
    char     name[32];
    int      pid;
    int      used;
    int      owner_uid;
    uint32_t mode;          /* service permission bits; "read" (4) gates lookup */
} services[MAX_SERVICES];

/* Unix-style rwx check against an owner/mode pair (no group concept yet). */
static int perm_ok(int uid, int owner, uint32_t mode, int want)
{
    if (uid == 0)
        return 1;
    int bits = (uid == owner) ? (int)((mode >> 6) & 7) : (int)(mode & 7);
    return (bits & want) == want;
}

static process_t *find_proc(int pid)
{
    for (int i = 0; i < MAX_PROCS; i++)
        if (proc_table[i].state == PROC_RUNNING && proc_table[i].pid == pid)
            return &proc_table[i];
    return NULL;
}

int sys_msgsend(int pid, const void *buf, int len)
{
    if (len < 0)
        return -1;
    if (len > MSG_MAX)
        len = MSG_MAX;
    if (len && !is_user_addr((uint32_t)buf, (size_t)len))
        return -1;                          /* reject a kernel/garbage buffer */

    process_t *dst = find_proc(pid);
    if (!dst)
        return -1;

    message_t *m = (message_t *)kmalloc(sizeof(message_t));
    if (!m)
        return -1;
    m->next = NULL;
    m->from = process_current()->pid;
    m->len  = len;
    memcpy(m->data, buf, (uint32_t)len);

    __asm__ volatile("cli");
    if (dst->mbox_count >= MBOX_LIMIT) {
        __asm__ volatile("sti");
        kfree(m);
        return -1;
    }
    if (dst->mbox_tail)
        dst->mbox_tail->next = m;
    else
        dst->mbox_head = m;
    dst->mbox_tail = m;
    dst->mbox_count++;
    if (dst->mbox_waiter) {
        thread_wake(dst->mbox_waiter);
        dst->mbox_waiter = NULL;
    }
    __asm__ volatile("sti");
    return 0;
}

int sys_msgrecv(void *buf, int len, int *from)
{
    int nowait = (len & MSG_NOWAIT) != 0;   /* high bit of len = don't block */
    len &= ~MSG_NOWAIT;
    process_t *p = process_current();

    if (len < 0)
        return -1;
    if (len && !is_user_addr((uint32_t)buf, (size_t)len))
        return -1;                          /* reject a kernel/garbage buffer */
    if (from && !is_user_addr((uint32_t)from, sizeof(int)))
        return -1;

    __asm__ volatile("cli");
    if (p->mbox_head == NULL && nowait) {
        __asm__ volatile("sti");
        return -1;                          /* mailbox empty: would block */
    }
    while (p->mbox_head == NULL) {
        p->mbox_waiter = thread_current();
        thread_block();
    }
    message_t *m = p->mbox_head;
    p->mbox_head = m->next;
    if (!p->mbox_head)
        p->mbox_tail = NULL;
    p->mbox_count--;
    __asm__ volatile("sti");

    int n = m->len;
    if (n > len)
        n = len;
    memcpy(buf, m->data, (uint32_t)n);
    if (from)
        *from = m->from;
    kfree(m);
    return n;
}

static void unregister_pid(int pid)
{
    for (int i = 0; i < MAX_SERVICES; i++)
        if (services[i].used && services[i].pid == pid)
            services[i].used = 0;
}

int sys_register(const char *name, uint32_t mode)
{
    int uid = process_current()->uid;
    int pid = process_current()->pid;
    /* Re-register an existing name only if owned by the caller (or by root):
     * this stops an unprivileged process from hijacking a service name. */
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (services[i].used && strcmp(services[i].name, name) == 0) {
            if (services[i].owner_uid != uid && uid != 0)
                return -1;
            services[i].pid = pid;
            services[i].owner_uid = uid;
            services[i].mode = mode;
            return 0;
        }
    }
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (!services[i].used) {
            int j = 0;
            while (name[j] && j < 31) { services[i].name[j] = name[j]; j++; }
            services[i].name[j] = '\0';
            services[i].pid = pid;
            services[i].owner_uid = uid;
            services[i].mode = mode;
            services[i].used = 1;
            return 0;
        }
    }
    return -1;
}

int sys_lookup(const char *name)
{
    int uid = process_current()->uid;
    for (int i = 0; i < MAX_SERVICES; i++)
        if (services[i].used && strcmp(services[i].name, name) == 0) {
            /* "read" permission gates discovery; a denied lookup looks absent. */
            if (!perm_ok(uid, services[i].owner_uid, services[i].mode, VFS_R))
                return -1;
            return services[i].pid;
        }
    return -1;
}

static process_t *get_init(void)
{
    for (int i = 0; i < MAX_PROCS; i++)
        if (proc_table[i].state == PROC_RUNNING && proc_table[i].pid == 1)
            return &proc_table[i];
    return NULL;
}

static void mailbox_clear(process_t *p)
{
    for (message_t *m = p->mbox_head; m; ) {
        message_t *n = m->next;
        kfree(m);
        m = n;
    }
    p->mbox_head = p->mbox_tail = NULL;
    p->mbox_count = 0;
}

/* Hand the dying process's children to init (pid 1). Zombies among them are
 * reaped by init's wait loop, so wake it if it is waiting. */
static void reparent_to_init(process_t *dying)
{
    process_t *in = get_init();
    if (!in || in == dying)
        return;
    for (int i = 0; i < MAX_PROCS; i++) {
        process_t *c = &proc_table[i];
        if (c->state != PROC_UNUSED && c != dying && c->parent == dying) {
            c->parent = in;
            c->ppid = in->pid;
            if (c->state == PROC_ZOMBIE && in->waiting)
                thread_wake(in->thread);
        }
    }
}

/* Forcibly terminate another process (the force-kill fallback for shutdown). */
int sys_kill(int pid)
{
    process_t *t = find_proc(pid);
    if (!t || t == process_current())
        return -1;

    close_all_fds(t);
    unregister_pid(t->pid);
    mailbox_clear(t);
    if (t->pd_phys) {
        vmm_destroy_address_space(t->pd_phys);
        t->pd_phys = 0;
    }
    if (t->thread) {
        thread_free(t->thread);
        t->thread = NULL;
    }
    t->exit_code = -9;
    t->state = PROC_ZOMBIE;

    reparent_to_init(t);
    if (t->parent && t->parent->waiting)
        thread_wake(t->parent->thread);
    return 0;
}

/* ---- sockets (loopback) + poll + uid ---- */

int sys_socket(int domain, int type)
{
    vfs_node_t *node = sock_create(domain, type);
    if (!node)
        return -1;
    int fd = fd_install_role(process_current(), node, FD_SOCKET);
    if (fd < 0) {
        sock_close(node);
        return -1;
    }
    return fd;
}

vfs_node_t *proc_socket_node(int pid, int fd)
{
    process_t *p = find_proc(pid);
    if (!p || fd < 0 || fd >= MAX_FDS || !p->fds[fd])
        return NULL;
    file_t *f = p->fds[fd];
    return (f->role == FD_SOCKET) ? f->node : NULL;
}

/* Wait until at least one descriptor is ready (POLLIN/POLLOUT) or, for fds that
 * are gone, POLLERR. timeout == 0 polls without blocking; otherwise blocks
 * until a socket peer makes progress. Non-socket fds are treated as ready (a
 * conservative default until pipes/console grow poll ops). */
int sys_poll(struct pollfd *fds, int nfds, int timeout)
{
    process_t *p = process_current();
    if (!fds || nfds < 0 || nfds > MAX_FDS)
        return -1;

    for (;;) {
        int ready = 0;
        __asm__ volatile("cli");
        for (int i = 0; i < nfds; i++) {
            fds[i].revents = 0;
            int fd = fds[i].fd;
            int want = fds[i].events;
            int re;
            if (fd < 0 || fd >= MAX_FDS || !p->fds[fd])
                re = POLLERR;
            else if (p->fds[fd]->role == FD_SOCKET)
                re = sock_poll(p->fds[fd]->node, want);
            else
                re = want & (POLLIN | POLLOUT);     /* non-sockets: assume ready */
            re &= (want | POLLERR);
            if (re) {
                fds[i].revents = (short)re;
                ready++;
            }
        }
        if (ready > 0 || timeout == 0) {
            __asm__ volatile("sti");
            return ready;
        }
        /* Arm a poll waiter on each socket fd, block, then disarm and re-scan. */
        for (int i = 0; i < nfds; i++) {
            int fd = fds[i].fd;
            if (fd >= 0 && fd < MAX_FDS && p->fds[fd] && p->fds[fd]->role == FD_SOCKET)
                sock_poll_arm(p->fds[fd]->node, thread_current());
        }
        thread_block();
        for (int i = 0; i < nfds; i++) {
            int fd = fds[i].fd;
            if (fd >= 0 && fd < MAX_FDS && p->fds[fd] && p->fds[fd]->role == FD_SOCKET)
                sock_poll_disarm(p->fds[fd]->node, thread_current());
        }
        __asm__ volatile("sti");
    }
}

int sys_getuid(void)
{
    return process_current()->uid;
}

/* Drop privilege only: root (uid 0) may become any uid; a non-root process may
 * never lower its uid number (i.e. cannot gain privilege). */
int sys_setuid(int uid)
{
    process_t *p = process_current();
    if (uid < 0)
        return -1;
    if (p->uid != 0 && uid < p->uid)
        return -1;
    p->uid = uid;
    return 0;
}

/* Owner uid of another process (e.g. so netd can enforce privileged ports), or
 * -1 if there is no such running process. */
int sys_uid_of(int pid)
{
    process_t *p = find_proc(pid);
    return p ? p->uid : -1;
}

/* ---- address-space + argv stack setup ---- */

/* Build argc/argv on the user stack of the *current* address space, returning
 * the resulting user esp. Layout (low to high): argc, argv[0..argc-1], NULL,
 * then the argument strings. */
static uint32_t setup_user_stack(int argc, char kargs[][ARG_LEN])
{
    uint32_t sp = USTACK_TOP;
    uint32_t argv_ptrs[MAX_ARG];

    for (int i = argc - 1; i >= 0; i--) {
        uint32_t len = (uint32_t)strlen(kargs[i]) + 1;
        sp -= len;
        memcpy((void *)sp, kargs[i], len);
        argv_ptrs[i] = sp;
    }

    sp &= ~3u;
    sp -= 4;
    *(uint32_t *)sp = 0;                         /* argv[argc] = NULL */
    for (int i = argc - 1; i >= 0; i--) {
        sp -= 4;
        *(uint32_t *)sp = argv_ptrs[i];
    }
    sp -= 4;
    *(uint32_t *)sp = (uint32_t)argc;            /* argc */
    return sp;
}

/* Create a new address space, load the ELF, map a user stack, and set up
 * argv. Leaves the previous address space active. */
static int load_image(const uint8_t *elf, uint32_t size, int argc,
                      char kargs[][ARG_LEN], uint32_t *pd_out,
                      uint32_t *entry_out, uint32_t *esp_out)
{
    uint32_t saved = vmm_current_directory();
    uint32_t pd    = vmm_create_address_space();
    vmm_switch_address_space(pd);

    uint32_t entry;
    if (elf_load(elf, size, &entry) != 0) {
        vmm_switch_address_space(saved);
        vmm_destroy_address_space(pd);
        return -1;
    }
    for (int i = 1; i <= USTACK_PAGES; i++)
        vmm_map_page(USTACK_TOP - (uint32_t)i * 0x1000, pmm_alloc_frame(),
                     PAGE_PRESENT | PAGE_WRITE | PAGE_USER);

    uint32_t esp = setup_user_stack(argc, kargs);

    vmm_switch_address_space(saved);
    *pd_out = pd;
    *entry_out = entry;
    *esp_out = esp;
    return 0;
}

void process_init(void)
{
    process_t *kp = alloc_proc();       /* pid 0: the kernel */
    kp->ppid = 0;
    kp->uid = 0;                        /* root */
    kp->pd_phys = vmm_kernel_directory();
    kp->thread = thread_current();
    kp->parent = NULL;
    thread_set_proc(thread_current(), kp);
}

int process_spawn(const uint8_t *elf, uint32_t size, const char *name)
{
    char kargs[1][ARG_LEN];
    int i = 0;
    while (name[i] && i < ARG_LEN - 1) { kargs[0][i] = name[i]; i++; }
    kargs[0][i] = '\0';

    uint32_t pd, entry, esp;
    if (load_image(elf, size, 1, kargs, &pd, &entry, &esp) != 0)
        return -1;

    process_t *p = alloc_proc();
    if (!p)
        return -1;
    p->pd_phys = pd;
    p->parent  = process_current();
    p->ppid    = p->parent ? p->parent->pid : 0;
    p->uid     = p->parent ? p->parent->uid : 0;
    p->user_brk = USER_HEAP_BASE;
    open_standard_streams(p);

    thread_t *t = thread_create_user(pd, entry, esp);
    p->thread = t;
    thread_set_proc(t, p);
    thread_start(t);            /* now safe to schedule */
    return p->pid;
}

/* ---- fork ---- */

extern void return_to_user(registers_t *r);
static void fork_child_entry(void)
{
    return_to_user((registers_t *)thread_start_arg(thread_current()));
}

static int copy_user_space(uint32_t child_pd)
{
    uint32_t *PD = (uint32_t *)0xFFFFF000;

    int count = 0;
    for (int pdi = 256; pdi < 768; pdi++) {
        if (!(PD[pdi] & PAGE_PRESENT))
            continue;
        uint32_t *PT = (uint32_t *)(0xFFC00000u + ((uint32_t)pdi << 12));
        for (int pti = 0; pti < 1024; pti++)
            if (PT[pti] & PAGE_PRESENT)
                count++;
    }

    uint32_t *vaddrs = (uint32_t *)kmalloc(sizeof(uint32_t) * (count ? count : 1));
    uint32_t *frames = (uint32_t *)kmalloc(sizeof(uint32_t) * (count ? count : 1));
    if (!vaddrs || !frames) {
        kfree(vaddrs);
        kfree(frames);
        return -1;
    }

    int k = 0;
    for (int pdi = 256; pdi < 768; pdi++) {
        if (!(PD[pdi] & PAGE_PRESENT))
            continue;
        uint32_t *PT = (uint32_t *)(0xFFC00000u + ((uint32_t)pdi << 12));
        for (int pti = 0; pti < 1024; pti++) {
            if (!(PT[pti] & PAGE_PRESENT))
                continue;
            uint32_t va = ((uint32_t)pdi << 22) | ((uint32_t)pti << 12);
            uint32_t cf = pmm_alloc_frame();
            void *tmp = vmm_temp_map(cf);
            memcpy(tmp, (void *)va, 0x1000);
            vmm_temp_unmap();
            vaddrs[k] = va;
            frames[k] = cf;
            k++;
        }
    }

    uint32_t saved = vmm_current_directory();
    vmm_switch_address_space(child_pd);
    for (int i = 0; i < k; i++)
        vmm_map_page(vaddrs[i], frames[i], PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
    vmm_switch_address_space(saved);

    kfree(vaddrs);
    kfree(frames);
    return 0;
}

int do_fork(registers_t *regs)
{
    process_t *parent = process_current();

    uint32_t child_pd = vmm_create_address_space();
    if (copy_user_space(child_pd) != 0) {
        vmm_destroy_address_space(child_pd);
        return -1;
    }

    process_t *child = alloc_proc();
    if (!child) {
        vmm_destroy_address_space(child_pd);
        return -1;
    }
    child->pd_phys = child_pd;
    child->parent  = parent;
    child->ppid    = parent->pid;
    child->uid     = parent->uid;
    child->user_brk = parent->user_brk;
    /* shm_mapped stays 0 (from alloc_proc's memset): copy_user_space deep-copies
     * the parent's shm pages into private frames (no PAGE_SHARED), so the child is
     * not a real mapper and must not touch the shared objects' refcounts. */

    for (int fd = 0; fd < MAX_FDS; fd++) {
        child->fds[fd] = parent->fds[fd];
        if (child->fds[fd])
            child->fds[fd]->refcount++;
    }

    child->saved_regs = *regs;
    child->saved_regs.eax = 0;          /* fork() returns 0 in the child */

    thread_t *t = thread_create_trampoline(child_pd, (uint32_t)fork_child_entry,
                                           &child->saved_regs);
    child->thread = t;
    thread_set_proc(t, child);
    thread_start(t);            /* now safe to schedule */

    return child->pid;                  /* parent's return value */
}

/* ---- exec ---- */

void do_exec(const char *path, char **argv, registers_t *regs)
{
    process_t *p = process_current();

    /* Copy the path and argv out of user memory before tearing the image down. */
    char kpath[128];
    int i = 0;
    while (path[i] && i < 127) { kpath[i] = path[i]; i++; }
    kpath[i] = '\0';

    char kargs[MAX_ARG][ARG_LEN];
    int argc = 0;
    if (argv) {
        while (argv[argc] && argc < MAX_ARG) {
            int j = 0;
            const char *a = argv[argc];
            while (a[j] && j < ARG_LEN - 1) { kargs[argc][j] = a[j]; j++; }
            kargs[argc][j] = '\0';
            argc++;
        }
    }
    if (argc == 0) {                    /* always pass argv[0] = program path */
        int j = 0;
        while (kpath[j] && j < ARG_LEN - 1) { kargs[0][j] = kpath[j]; j++; }
        kargs[0][j] = '\0';
        argc = 1;
    }

    vfs_node_t *f = vfs_resolve(kpath);
    if (!f) {
        regs->eax = (uint32_t)-1;
        return;
    }
    if (!vfs_permitted(f, p->uid, VFS_X)) {     /* must be executable by us */
        regs->eax = (uint32_t)-1;
        return;
    }
    uint8_t *buf = (uint8_t *)kmalloc(f->size);
    if (!buf) {
        regs->eax = (uint32_t)-1;
        return;
    }
    vfs_read(f, 0, f->size, buf);

    uint32_t new_pd, entry, esp;
    if (load_image(buf, f->size, argc, kargs, &new_pd, &entry, &esp) != 0) {
        kfree(buf);
        regs->eax = (uint32_t)-1;
        return;
    }
    kfree(buf);

    uint32_t old_pd = p->pd_phys;
    shm_release_proc(p);                /* the old image's shm mappings are gone */
    vmm_switch_address_space(vmm_kernel_directory());
    vmm_destroy_address_space(old_pd);

    p->pd_phys = new_pd;
    p->user_brk = USER_HEAP_BASE;
    thread_set_pd(p->thread, new_pd);
    vmm_switch_address_space(new_pd);

    registers_t r;
    memset(&r, 0, sizeof(r));
    r.ds      = USER_DATA;
    r.eip     = entry;
    r.cs      = USER_CODE;
    r.eflags  = 0x202;
    r.useresp = esp;
    r.ss      = USER_DATA;
    return_to_user(&r);
}

/* ---- exit / wait ---- */

void process_exit(int code)
{
    process_t *p = process_current();

    close_all_fds(p);

    /* Drop any pending messages and named-service registrations. */
    unregister_pid(p->pid);
    mailbox_clear(p);
    shm_release_proc(p);                /* drop shm mappings + free objects it owns */

    vmm_switch_address_space(vmm_kernel_directory());
    vmm_destroy_address_space(p->pd_phys);
    p->pd_phys = 0;

    p->exit_code = code;
    p->state = PROC_ZOMBIE;

    /* Orphaned children are adopted by init. */
    reparent_to_init(p);

    if (p->parent && p->parent->waiting)
        thread_wake(p->parent->thread);

    thread_zombie_and_yield();      /* never returns */
}

static process_t *find_zombie_child(process_t *parent, int pid)
{
    for (int i = 0; i < MAX_PROCS; i++) {
        process_t *c = &proc_table[i];
        if (c->state == PROC_ZOMBIE && c->parent == parent &&
            (pid < 0 || c->pid == pid))
            return c;
    }
    return NULL;
}

static int has_children(process_t *parent)
{
    for (int i = 0; i < MAX_PROCS; i++) {
        process_t *c = &proc_table[i];
        if (c->state != PROC_UNUSED && c->parent == parent)
            return 1;
    }
    return 0;
}

int process_wait(int pid, int *status_user, int nohang)
{
    process_t *p = process_current();

    for (;;) {
        __asm__ volatile("cli");

        process_t *child = find_zombie_child(p, pid);
        if (child) {
            int cpid = child->pid;
            int code = child->exit_code;
            __asm__ volatile("sti");

            if (status_user)
                *status_user = code;

            if (child->thread) {        /* may already be freed by sys_kill */
                thread_free(child->thread);
                child->thread = NULL;
            }
            child->state = PROC_UNUSED;
            return cpid;
        }

        if (!has_children(p)) {
            __asm__ volatile("sti");
            return -1;              /* no children at all */
        }

        if (nohang) {
            __asm__ volatile("sti");
            return 0;              /* children exist, none ready */
        }

        p->waiting = 1;
        thread_block();
        p->waiting = 0;
    }
}
