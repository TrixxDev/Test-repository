/* Global Descriptor Table + Task State Segment setup. */
#pragma once
#include <stdint.h>

void gdt_install(void);

/* Update the ring-0 stack pointer the CPU switches to on a ring 3 -> 0 trap. */
void tss_set_kernel_stack(uint32_t esp0);
