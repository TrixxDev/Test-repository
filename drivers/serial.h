/* Serial port (COM1) driver, used for kernel logging under QEMU. */
#pragma once

void serial_init(void);
void serial_write_char(char c);
