/* Global Descriptor Table + Task State Segment setup. */
#pragma once
#include <stdint.h>

void gdt_install(void);

/* Update the ring-0 stack pointer the CPU switches to on a ring 3 -> 0 trap. */
void tss_set_kernel_stack(uint32_t esp0);

/* Phase 18.5.6: a second TSS (GDT index 6) that vector 8 (#DF) is wired to
 * as a TASK GATE, not a normal interrupt gate -- see arch/i386/isr.c. A
 * same-privilege (ring0->ring0) interrupt gate delivers its exception frame
 * onto the CURRENT stack; if that stack is itself invalid (a kernel stack
 * overflow into an unmapped guard page is exactly this), the CPU immediately
 * re-faults trying to push that very frame, escalating page-fault-during-
 * page-fault to a double fault -- which, on an ordinary interrupt gate,
 * re-faults the SAME way trying to deliver *itself*, guaranteeing a triple
 * fault with no diagnostic at all. A task gate is the one thing that avoids
 * this: the hardware task switch loads an entirely fresh set of registers
 * (including ESP/SS) from a separate TSS *before* executing a single
 * instruction of the handler, so it needs no stack space from the faulting
 * context to get started. */
#define DF_TSS_SELECTOR 0x30

/* paging_init() must run first (gdt_install() itself runs before paging is
 * even enabled, so CR3 isn't meaningful yet) -- called once from kmain.c
 * right after paging_init() with vmm_kernel_directory(). Kernel-space
 * mappings (where the emergency stack, its handler code, and every guard
 * page live) are identical under every process's page directory by
 * construction, so which one this points to doesn't otherwise matter. */
void gdt_df_tss_set_cr3(uint32_t cr3);

/* On a task-gate-triggered switch, the CPU saves the OUTGOING (faulting)
 * task's register state into whatever TSS the (never-task-switched-until-
 * now) TR register still references -- the main TSS from write_tss() above.
 * Reads eip/esp from it: the last thing the CPU was doing before the
 * cascade made the original page fault handler unreachable. */
void gdt_get_last_fault_state(uint32_t *eip, uint32_t *esp);
