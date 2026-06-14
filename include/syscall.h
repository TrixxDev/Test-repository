/* System call interface (int 0x80).
 * Convention: eax = number, ebx/ecx/edx = args, eax = return value. */
#pragma once
#include "isr.h"

#define SYS_PUTC   1
#define SYS_YIELD  2
#define SYS_EXIT   3
#define SYS_FORK   4
#define SYS_EXEC   5
#define SYS_WAIT   6
#define SYS_OPEN   7
#define SYS_READ   8
#define SYS_WRITE  9
#define SYS_CLOSE  10
#define SYS_GETPID 11

/* Dispatched from the interrupt handler for vector 0x80. */
void syscall_handler(registers_t *regs);
