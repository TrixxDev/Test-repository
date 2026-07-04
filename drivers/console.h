/* Console device exposed as a VFS node, used for stdin/stdout/stderr. */
#pragma once
#include "vfs.h"

vfs_node_t *console_node(void);

/* Called by the keyboard and serial drivers' IRQ handlers after buffering a
 * byte, to wake a thread blocked in console_read() waiting on either
 * source. */
void console_notify(void);
