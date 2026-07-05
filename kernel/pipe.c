#include "pipe.h"
#include "kheap.h"
#include "scheduler.h"
#include "string.h"
#include "syscall_abi.h"   /* O_NONBLOCK, EAGAIN */

#define PIPE_BUF 4096

typedef struct pipe {
    uint8_t  buf[PIPE_BUF];
    int      head, tail, count;
    int      readers, writers;
    wait_queue_t rwq;       /* Phase 18.2: readers blocked on empty (was a lone thread_t*) */
    wait_queue_t wwq;       /* writers blocked on full */
    vfs_node_t *rnode, *wnode;
} pipe_t;

static int pipe_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *out, int flags)
{
    (void)off;
    pipe_t *p = (pipe_t *)node->priv;
    uint32_t n = 0;
    int nonblock = (flags & O_NONBLOCK) != 0;

    __asm__ volatile("cli");
    while (p->count == 0 && p->writers > 0) {
        if (nonblock) {
            __asm__ volatile("sti");
            return -EAGAIN;
        }
        wait_enqueue(&p->rwq);      /* yields with interrupts off */
    }
    while (n < size && p->count > 0) {
        out[n++] = p->buf[p->head];
        p->head = (p->head + 1) % PIPE_BUF;
        p->count--;
    }
    wait_wake_one(&p->wwq);
    __asm__ volatile("sti");
    return (int)n;              /* 0 == EOF (all writers closed) */
}

static int pipe_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *in, int flags)
{
    (void)off;
    pipe_t *p = (pipe_t *)node->priv;
    uint32_t n = 0;
    int nonblock = (flags & O_NONBLOCK) != 0;

    __asm__ volatile("cli");
    while (n < size) {
        while (p->count == PIPE_BUF && p->readers > 0) {
            if (nonblock) {
                __asm__ volatile("sti");
                return n ? (int)n : -EAGAIN;
            }
            wait_enqueue(&p->wwq);
        }
        if (p->readers == 0) {          /* broken pipe */
            __asm__ volatile("sti");
            return n ? (int)n : -1;
        }
        while (n < size && p->count < PIPE_BUF) {
            p->buf[p->tail] = in[n++];
            p->tail = (p->tail + 1) % PIPE_BUF;
            p->count++;
        }
        wait_wake_one(&p->rwq);
    }
    __asm__ volatile("sti");
    return (int)n;
}

static vfs_ops_t pipe_read_ops  = { .read = pipe_read };
static vfs_ops_t pipe_write_ops = { .write = pipe_write };

int pipe_create(vfs_node_t **rnode, vfs_node_t **wnode)
{
    pipe_t *p = (pipe_t *)kmalloc(sizeof(pipe_t));
    vfs_node_t *rn = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    vfs_node_t *wn = (vfs_node_t *)kmalloc(sizeof(vfs_node_t));
    if (!p || !rn || !wn) {
        kfree(p); kfree(rn); kfree(wn);
        return -1;
    }
    memset(p, 0, sizeof(*p));
    memset(rn, 0, sizeof(*rn));
    memset(wn, 0, sizeof(*wn));

    p->readers = 1;
    p->writers = 1;
    p->rnode = rn;
    p->wnode = wn;

    rn->flags = VFS_FILE; rn->mode = 0600; rn->ops = &pipe_read_ops;  rn->priv = p;
    wn->flags = VFS_FILE; wn->mode = 0600; wn->ops = &pipe_write_ops; wn->priv = p;

    *rnode = rn;
    *wnode = wn;
    return 0;
}

void pipe_close_end(vfs_node_t *node, int is_write)
{
    pipe_t *p = (pipe_t *)node->priv;

    __asm__ volatile("cli");
    if (is_write) {
        p->writers--;
        wait_wake_all(&p->rwq);     /* every blocked reader should notice EOF */
    } else {
        p->readers--;
        wait_wake_all(&p->wwq);     /* every blocked writer should notice the broken pipe */
    }
    int dead = (p->readers <= 0 && p->writers <= 0);
    __asm__ volatile("sti");

    if (dead) {
        kfree(p->rnode);
        kfree(p->wnode);
        kfree(p);
    }
}
