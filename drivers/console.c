#include "console.h"
#include "keyboard.h"
#include "kio.h"

static int console_read(vfs_node_t *node, uint32_t off, uint32_t size, uint8_t *buf)
{
    (void)node;
    (void)off;
    uint32_t n = 0;
    while (n < size) {
        int c = keyboard_getchar();
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
