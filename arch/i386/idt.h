/* Interrupt Descriptor Table setup. */
#pragma once
#include <stdint.h>

void idt_set_gate(uint8_t num, uint32_t base, uint16_t selector, uint8_t flags);
void idt_install(void);
