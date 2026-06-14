#include "process.h"
#include "paging.h"
#include "pmm.h"
#include "elf.h"
#include "scheduler.h"
#include "kheap.h"
#include "string.h"
#include "kio.h"
#include "console.h"

#define MAX_PROCS    32
#define USTACK_TOP   0xC0000000u
#define USTACK_PAGES 4

#define USER_CODE 0x1B
#define USER_DATA 0x23

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

static int fd_install(process_t *p, vfs_node_t *node)
{
    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (!p->fds[fd]) {
            file_t *f = (file_t *)kmalloc(sizeof(file_t));
            if (!f)
                return -1;
            f->node = node;
            f->offset = 0;
            f->refcount = 1;
            p->fds[fd] = f;
            return fd;
        }
    }
    return -1;
}

static void open_standard_streams(process_t *p)
{
    /* 0=stdin, 1=stdout, 2=stderr all wired to the console device. */
    vfs_node_t *con = console_node();
    for (int fd = 0; fd < 3; fd++) {
        file_t *f = (file_t *)kmalloc(sizeof(file_t));
        f->node = con;
        f->offset = 0;
        f->refcount = 1;
        p->fds[fd] = f;
    }
}

static void close_all_fds(process_t *p)
{
    for (int fd = 0; fd < MAX_FDS; fd++) {
        file_t *f = p->fds[fd];
        if (f && --f->refcount == 0)
            kfree(f);
        p->fds[fd] = NULL;
    }
}

int sys_open(const char *path, int flags)
{
    (void)flags;
    process_t *p = process_current();
    vfs_node_t *node = vfs_resolve(path);
    if (!node)
        return -1;
    return fd_install(p, node);
}

int sys_read(int fd, void *buf, uint32_t len)
{
    process_t *p = process_current();
    if (fd < 0 || fd >= MAX_FDS || !p->fds[fd])
        return -1;
    file_t *f = p->fds[fd];
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
    file_t *f = p->fds[fd];
    if (--f->refcount == 0)
        kfree(f);
    p->fds[fd] = NULL;
    return 0;
}

/* ---- creation ---- */

void process_init(void)
{
    process_t *kp = alloc_proc();       /* pid 0: the kernel */
    kp->ppid = 0;
    kp->pd_phys = vmm_kernel_directory();
    kp->thread = thread_current();
    kp->parent = NULL;
    thread_set_proc(thread_current(), kp);
}

static int load_into_new_space(const uint8_t *elf, uint32_t size,
                               uint32_t *pd_out, uint32_t *entry_out)
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

    vmm_switch_address_space(saved);
    *pd_out = pd;
    *entry_out = entry;
    return 0;
}

int process_spawn(const uint8_t *elf, uint32_t size)
{
    uint32_t pd, entry;
    if (load_into_new_space(elf, size, &pd, &entry) != 0)
        return -1;

    process_t *p = alloc_proc();
    if (!p)
        return -1;
    p->pd_phys = pd;
    p->parent  = process_current();
    p->ppid    = p->parent ? p->parent->pid : 0;
    open_standard_streams(p);

    thread_t *t = thread_create_user(pd, entry, USTACK_TOP);
    p->thread = t;
    thread_set_proc(t, p);
    return p->pid;
}

/* ---- fork ---- */

/* Trampoline for a forked child: return to ring 3 using the copied frame. */
extern void return_to_user(registers_t *r);
static void fork_child_entry(void)
{
    return_to_user((registers_t *)thread_start_arg(thread_current()));
}

/* Copy every present user page of the current address space into `child_pd`. */
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

    /* Inherit the descriptor table (shared open files). */
    for (int fd = 0; fd < MAX_FDS; fd++) {
        child->fds[fd] = parent->fds[fd];
        if (child->fds[fd])
            child->fds[fd]->refcount++;
    }

    /* Child resumes exactly where the parent was, but fork() returns 0. */
    child->saved_regs = *regs;
    child->saved_regs.eax = 0;

    thread_t *t = thread_create_trampoline(child_pd, (uint32_t)fork_child_entry,
                                           &child->saved_regs);
    child->thread = t;
    thread_set_proc(t, child);

    return child->pid;      /* parent's return value */
}

/* ---- exec ---- */

void do_exec(const char *path, registers_t *regs)
{
    process_t *p = process_current();

    /* Copy the path out of user memory before we tear the image down. */
    char kpath[128];
    int i = 0;
    while (path[i] && i < 127) {
        kpath[i] = path[i];
        i++;
    }
    kpath[i] = '\0';

    vfs_node_t *f = vfs_resolve(kpath);
    if (!f) {
        regs->eax = (uint32_t)-1;
        return;
    }
    uint8_t *buf = (uint8_t *)kmalloc(f->size);
    if (!buf) {
        regs->eax = (uint32_t)-1;
        return;
    }
    vfs_read(f, 0, f->size, buf);

    uint32_t new_pd, entry;
    if (load_into_new_space(buf, f->size, &new_pd, &entry) != 0) {
        kfree(buf);
        regs->eax = (uint32_t)-1;
        return;
    }
    kfree(buf);

    uint32_t old_pd = p->pd_phys;

    /* Leave the old space before freeing it. */
    vmm_switch_address_space(vmm_kernel_directory());
    vmm_destroy_address_space(old_pd);

    p->pd_phys = new_pd;
    thread_set_pd(p->thread, new_pd);
    vmm_switch_address_space(new_pd);

    /* Jump into the new image with a clean ring-3 frame. */
    registers_t r;
    memset(&r, 0, sizeof(r));
    r.ds      = USER_DATA;
    r.eip     = entry;
    r.cs      = USER_CODE;
    r.eflags  = 0x202;
    r.useresp = USTACK_TOP;
    r.ss      = USER_DATA;
    return_to_user(&r);
}

/* ---- exit / wait ---- */

void process_exit(int code)
{
    process_t *p = process_current();

    close_all_fds(p);

    /* Free the user address space (after leaving it). */
    vmm_switch_address_space(vmm_kernel_directory());
    vmm_destroy_address_space(p->pd_phys);
    p->pd_phys = 0;

    p->exit_code = code;
    p->state = PROC_ZOMBIE;

    /* Wake the parent if it is waiting. */
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

int process_wait(int pid, int *status_user)
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

            thread_free(child->thread);
            child->state = PROC_UNUSED;     /* reap the PCB */
            return cpid;
        }

        if (!has_children(p)) {
            __asm__ volatile("sti");
            return -1;
        }

        /* Block until a child exits. */
        p->waiting = 1;
        thread_block();                     /* yields with interrupts off */
        p->waiting = 0;
    }
}
