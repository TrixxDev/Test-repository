/* Interrupt service routines and IRQ dispatch. */
#pragma once
#include <stdint.h>

/* CPU register state captured by the interrupt stubs. The field order must
 * match the push order in interrupt.S exactly. */
typedef struct {
    uint32_t ds;                                   /* data segment, pushed by us */
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax; /* pusha */
    uint32_t int_no, err_code;                     /* interrupt number + error code */
    uint32_t eip, cs, eflags, useresp, ss;         /* pushed by the CPU */
} registers_t;

typedef void (*isr_t)(registers_t *);

/* Installs CPU exception gates (0-31) and hardware IRQ gates (32-47),
 * and remaps the PIC. Call after idt_install(). */
void isr_install(void);

/* Register a handler for an interrupt vector (e.g. 32 = timer, 33 = keyboard). */
void register_interrupt_handler(uint8_t n, isr_t handler);
