/* Console device exposed as a VFS node, used for stdin/stdout/stderr. */
#pragma once
#include "vfs.h"
#include "scheduler.h"      /* wait_queue_t */

vfs_node_t *console_node(void);

/* Called by the keyboard and serial drivers' IRQ handlers after buffering a
 * byte, to wake a thread blocked in console_read() waiting on either
 * source. */
void console_notify(void);

/* Phase 18.3: readiness for wait_events()/poll() -- POLLOUT is always set
 * (console_write() never blocks); POLLIN is set once a byte is buffered
 * from either input source. Call with interrupts disabled. */
int console_poll(int events);

/* The wait queue a console reader blocks on, shared by wait_events() pollers. */
wait_queue_t *console_waitq(void);
