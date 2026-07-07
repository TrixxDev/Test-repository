/* Kernel-side system call dispatch. Numbers live in syscall_abi.h. */
#pragma once
#include "isr.h"
#include "syscall_abi.h"

/* Dispatched from the interrupt handler for vector 0x80. */
void syscall_handler(registers_t *regs);
