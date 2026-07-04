/* Serial port (COM1) driver, used for kernel logging under QEMU and, since
 * Phase 18.0, as a fast test/automation command channel: bytes typed into the
 * QEMU serial chardev arrive here instead of being scancode-injected through
 * the monitor's `sendkey`. */
#pragma once

void serial_init(void);
void serial_write_char(char c);

/* Enables the RX ("data available") interrupt and registers its handler.
 * Call once, after isr_install(). */
void serial_install(void);

/* Non-blocking: returns the next received byte, or -1 if none is buffered. */
int serial_trygetchar(void);
