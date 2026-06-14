/* System call interface (int 0x80). */
#pragma once
#include "isr.h"

#define SYS_PUTC  1
#define SYS_YIELD 2
#define SYS_EXIT  3

/* Dispatched from the interrupt handler for vector 0x80. */
void syscall_handler(registers_t *regs);
