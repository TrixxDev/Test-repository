#include "console.h"
#include "keyboard.h"
#include "serial.h"
#include "kio.h"
#include "scheduler.h"

/* One waiter: only one thread (the shell's read(0, ...)) ever blocks here at
 * a time. Woken by either driver's IRQ handler via console_notify(), the
 * same single-waiter pattern keyboard.c used before Phase 18.0 -- now
 * shared because two independent interrupt sources feed the same console. */
static thread_t *waiter;

void console_notify(void)
{
    if (waiter) {
        thread_wake(waiter);
        waiter = NULL;
    }
}

/* Blocks until a byte arrives from either the keyboard or the serial command
 * channel (Phase 18.0), whichever is first. Both sources are checked in one
 * interrupts-off window so a byte that arrives between the check and
 * thread_block() can't be missed (lost wakeup): keyboard_trygetchar() and
 * serial_trygetchar() assume the caller already holds interrupts off. Serial
 * bytes are echoed here (the keyboard driver already echoes its own locally)
 * so a byte typed over serial is visible in the same log a QEMU test reads
 * back from that same serial port. */
static int console_getchar(void)
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
        waiter = thread_current();
        thread_block();     /* yields with interrupts off; resumes on input */
    }
}

static int console_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf)
{
    (void)node;
    (void)off;
    uint32_t n = 0;
    while (n < size) {
        int c = console_getchar();
        buf[n++] = (uint8_t)c;
        if (c == '\n')
            break;
    }
    return (int)n;
}

static int console_write(vfs_node_t *node, uint32_t off, uint32_t size, const uint8_t *buf)
{
    (void)node;
    (void)off;
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
