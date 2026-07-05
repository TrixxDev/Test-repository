#include "console.h"
#include "keyboard.h"
#include "serial.h"
#include "kio.h"
#include "scheduler.h"
#include "syscall_abi.h"   /* O_NONBLOCK, EAGAIN */

/* Phase 18.1.4: the first migration off a hand-rolled single-waiter field
 * onto the shared kernel wait_queue_t (kernel/scheduler.h) -- proof that the
 * general primitive is a correct, drop-in replacement for exactly the
 * pattern Phase 18.0 hand-rolled here (and that keyboard.c/serial.c's IRQ
 * handlers, unchanged, wake it correctly through the same console_notify()
 * they already call). Multiple waiters would now also work correctly (only
 * one ever exists in practice today: the shell's read(0, ...)), which the
 * old single-`thread_t *` field could not have supported. */
static wait_queue_t console_wq = WAIT_QUEUE_INIT;

void console_notify(void)
{
    wait_wake_one(&console_wq);
}

/* Blocks until a byte arrives from either the keyboard or the serial command
 * channel (Phase 18.0), whichever is first -- unless `nonblock`, in which
 * case it returns -EAGAIN instead of waiting (Phase 18.2). Both sources are
 * checked in one interrupts-off window so a byte that arrives between the
 * check and wait_enqueue() can't be missed (lost wakeup): keyboard_trygetchar()
 * and serial_trygetchar() assume the caller already holds interrupts off.
 * Serial bytes are echoed here (the keyboard driver already echoes its own
 * locally) so a byte typed over serial is visible in the same log a QEMU
 * test reads back from that same serial port. */
static int console_getchar(int nonblock)
{
    for (;;) {
        __asm__ volatile("cli");
        int c = keyboard_trygetchar();
        int from_serial = 0;
        if (c < 0) {
            c = serial_trygetchar();
            from_serial = (c >= 0);
        }
        if (c >= 0) {
            __asm__ volatile("sti");
            if (from_serial)
                kputchar((char)c);
            return c;
        }
        if (nonblock) {
            __asm__ volatile("sti");
            return -EAGAIN;
        }
        wait_enqueue(&console_wq);   /* yields with interrupts off; resumes on input */
    }
}

static int console_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf, int flags)
{
    (void)node;
    (void)off;
    int nonblock = (flags & O_NONBLOCK) != 0;
    uint32_t n = 0;
    while (n < size) {
        int c = console_getchar(nonblock);
        if (c == -EAGAIN)
            return n ? (int)n : -EAGAIN;   /* a partial read is a success, not EAGAIN */
        buf[n++] = (uint8_t)c;
        if (c == '\n')
            break;
    }
    return (int)n;
}

static int console_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf, int flags)
{
    (void)node;
    (void)off;
    (void)flags;    /* writing to the console never blocks */
    for (uint32_t i = 0; i < size; i++)
        kputchar((char)buf[i]);
    return (int)size;
}

static vfs_ops_t console_ops = {
    .read    = console_read,
    .write   = console_write,
    .finddir = NULL,
    .readdir = NULL,
    .create  = NULL,
};

static vfs_node_t con = {
    .name      = "console",
    .flags     = VFS_FILE,
    .mode      = 0666,          /* rw for everyone (shared terminal) */
    .owner_uid = 0,
    .ops       = &console_ops,
};

vfs_node_t *console_node(void)
{
    return &con;
}
