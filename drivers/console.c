#include "console.h"
#include "keyboard.h"
#include "serial.h"
#include "kio.h"
#include "scheduler.h"

/* Blocks until a byte arrives from either the keyboard or the serial command
 * channel (Phase 18.0), whichever is first. Neither driver's buffer can
 * starve the other since both are polled non-blockingly each pass. Serial
 * bytes are echoed here (the keyboard driver already echoes its own locally)
 * so a byte typed over serial is visible in the same log a QEMU test reads
 * back from that same serial port. */
static int console_getchar(void)
{
    for (;;) {
        int c = keyboard_trygetchar();
        if (c >= 0)
            return c;
        c = serial_trygetchar();
        if (c >= 0) {
            kputchar((char)c);
            return c;
        }
        schedule();
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
