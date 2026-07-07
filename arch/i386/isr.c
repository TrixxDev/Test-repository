#include "isr.h"
#include "idt.h"
#include "io.h"
#include "kio.h"
#include "syscall.h"
#include "scheduler.h"
#include "gdt.h"

/* Exception stubs (isr0..isr31) and IRQ stubs (irq0..irq15) from interrupt.S. */
extern void isr0(void);  extern void isr1(void);  extern void isr2(void);
extern void isr3(void);  extern void isr4(void);  extern void isr5(void);
extern void isr6(void);  extern void isr7(void);  extern void isr8(void);
extern void isr9(void);  extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void);
extern void isr15(void); extern void isr16(void); extern void isr17(void);
extern void isr18(void); extern void isr19(void); extern void isr20(void);
extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void);
extern void isr27(void); extern void isr28(void); extern void isr29(void);
extern void isr30(void); extern void isr31(void);

extern void irq0(void);  extern void irq1(void);  extern void irq2(void);
extern void irq3(void);  extern void irq4(void);  extern void irq5(void);
extern void irq6(void);  extern void irq7(void);  extern void irq8(void);
extern void irq9(void);  extern void irq10(void); extern void irq11(void);
extern void irq12(void); extern void irq13(void); extern void irq14(void);
extern void irq15(void);

extern void isr128(void);   /* int 0x80 system call gate */

static isr_t handlers[256];

/* Remap the 8259 PIC so IRQs 0-15 arrive as interrupts 32-47, keeping them
 * clear of the CPU's reserved exception vectors. */
static void pic_remap(void)
{
    outb(0x20, 0x11); io_wait();   /* start init, cascade mode (master) */
    outb(0xA0, 0x11); io_wait();   /* start init (slave) */
    outb(0x21, 0x20); io_wait();   /* master offset -> 32 */
    outb(0xA1, 0x28); io_wait();   /* slave offset  -> 40 */
    outb(0x21, 0x04); io_wait();   /* tell master about slave at IRQ2 */
    outb(0xA1, 0x02); io_wait();   /* tell slave its cascade identity */
    outb(0x21, 0x01); io_wait();   /* 8086/88 mode */
    outb(0xA1, 0x01); io_wait();
    outb(0x21, 0x00);              /* unmask all on master */
    outb(0xA1, 0x00);             /* unmask all on slave */
}

void isr_install(void)
{
    pic_remap();

    idt_set_gate(0,  (uint32_t)isr0,  0x08, 0x8E);
    idt_set_gate(1,  (uint32_t)isr1,  0x08, 0x8E);
    idt_set_gate(2,  (uint32_t)isr2,  0x08, 0x8E);
    idt_set_gate(3,  (uint32_t)isr3,  0x08, 0x8E);
    idt_set_gate(4,  (uint32_t)isr4,  0x08, 0x8E);
    idt_set_gate(5,  (uint32_t)isr5,  0x08, 0x8E);
    idt_set_gate(6,  (uint32_t)isr6,  0x08, 0x8E);
    idt_set_gate(7,  (uint32_t)isr7,  0x08, 0x8E);
    /* Phase 18.5.6: vector 8 (#DF) is a TASK GATE, not an interrupt gate --
     * see gdt.h's DF_TSS_SELECTOR comment for why a same-privilege interrupt
     * gate can't reliably deliver a double fault caused by a broken stack.
     * `base` is unused/ignored by hardware for a task gate. */
    idt_set_gate(8,  0,               DF_TSS_SELECTOR, 0x85);
    idt_set_gate(9,  (uint32_t)isr9,  0x08, 0x8E);
    idt_set_gate(10, (uint32_t)isr10, 0x08, 0x8E);
    idt_set_gate(11, (uint32_t)isr11, 0x08, 0x8E);
    idt_set_gate(12, (uint32_t)isr12, 0x08, 0x8E);
    idt_set_gate(13, (uint32_t)isr13, 0x08, 0x8E);
    idt_set_gate(14, (uint32_t)isr14, 0x08, 0x8E);
    idt_set_gate(15, (uint32_t)isr15, 0x08, 0x8E);
    idt_set_gate(16, (uint32_t)isr16, 0x08, 0x8E);
    idt_set_gate(17, (uint32_t)isr17, 0x08, 0x8E);
    idt_set_gate(18, (uint32_t)isr18, 0x08, 0x8E);
    idt_set_gate(19, (uint32_t)isr19, 0x08, 0x8E);
    idt_set_gate(20, (uint32_t)isr20, 0x08, 0x8E);
    idt_set_gate(21, (uint32_t)isr21, 0x08, 0x8E);
    idt_set_gate(22, (uint32_t)isr22, 0x08, 0x8E);
    idt_set_gate(23, (uint32_t)isr23, 0x08, 0x8E);
    idt_set_gate(24, (uint32_t)isr24, 0x08, 0x8E);
    idt_set_gate(25, (uint32_t)isr25, 0x08, 0x8E);
    idt_set_gate(26, (uint32_t)isr26, 0x08, 0x8E);
    idt_set_gate(27, (uint32_t)isr27, 0x08, 0x8E);
    idt_set_gate(28, (uint32_t)isr28, 0x08, 0x8E);
    idt_set_gate(29, (uint32_t)isr29, 0x08, 0x8E);
    idt_set_gate(30, (uint32_t)isr30, 0x08, 0x8E);
    idt_set_gate(31, (uint32_t)isr31, 0x08, 0x8E);

    idt_set_gate(32, (uint32_t)irq0,  0x08, 0x8E);
    idt_set_gate(33, (uint32_t)irq1,  0x08, 0x8E);
    idt_set_gate(34, (uint32_t)irq2,  0x08, 0x8E);
    idt_set_gate(35, (uint32_t)irq3,  0x08, 0x8E);
    idt_set_gate(36, (uint32_t)irq4,  0x08, 0x8E);
    idt_set_gate(37, (uint32_t)irq5,  0x08, 0x8E);
    idt_set_gate(38, (uint32_t)irq6,  0x08, 0x8E);
    idt_set_gate(39, (uint32_t)irq7,  0x08, 0x8E);
    idt_set_gate(40, (uint32_t)irq8,  0x08, 0x8E);
    idt_set_gate(41, (uint32_t)irq9,  0x08, 0x8E);
    idt_set_gate(42, (uint32_t)irq10, 0x08, 0x8E);
    idt_set_gate(43, (uint32_t)irq11, 0x08, 0x8E);
    idt_set_gate(44, (uint32_t)irq12, 0x08, 0x8E);
    idt_set_gate(45, (uint32_t)irq13, 0x08, 0x8E);
    idt_set_gate(46, (uint32_t)irq14, 0x08, 0x8E);
    idt_set_gate(47, (uint32_t)irq15, 0x08, 0x8E);

    /* System call gate: DPL 3 so ring 3 code may invoke `int 0x80`. */
    idt_set_gate(0x80, (uint32_t)isr128, 0x08, 0xEE);
}

void register_interrupt_handler(uint8_t n, isr_t handler)
{
    handlers[n] = handler;
}

static const char *exception_messages[32] = {
    "Division by zero",
    "Debug",
    "Non-maskable interrupt",
    "Breakpoint",
    "Overflow",
    "Bound range exceeded",
    "Invalid opcode",
    "Device not available",
    "Double fault",
    "Coprocessor segment overrun",
    "Invalid TSS",
    "Segment not present",
    "Stack-segment fault",
    "General protection fault",
    "Page fault",
    "Reserved",
    "x87 floating-point exception",
    "Alignment check",
    "Machine check",
    "SIMD floating-point exception",
    "Virtualization exception",
    "Control protection exception",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved",
};

/* Phase 18.5.6: entered by a hardware task switch (vector 8's task gate),
 * never by a normal `call` -- runs on df_tss's own dedicated stack, so it
 * needs none of the (possibly exhausted) stack that caused the double fault
 * in the first place. gdt_get_last_fault_state() reads the outgoing task's
 * eip/esp, which the CPU saved into the main TSS as part of the switch (this
 * kernel never does a hardware task switch otherwise, so TR still points at
 * that one TSS) -- CR2 itself isn't preserved across the cascade, but in
 * this kernel a double fault reaching here is overwhelmingly a kernel stack
 * overflow (nothing else is expected to fault while already handling a
 * fault), so the message says so plainly instead of just "Double fault". */
void df_handler_entry(void)
{
    uint32_t eip, esp;
    gdt_get_last_fault_state(&eip, &esp);
    kprintf("\n*** DOUBLE FAULT -- almost certainly a kernel stack overflow: the very\n"
            "    first attempt to deliver the page fault itself needed a stack slot\n"
            "    that was ALSO unmapped, so the page-fault handler never got to run\n"
            "    (last known eip=0x%x esp=0x%x before the cascade)\n", eip, esp);
    kprintf("*** System halted.\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* Called from the assembly stub for CPU exceptions (vectors 0-31). */
void isr_handler(registers_t *regs)
{
    if (regs->int_no == 0x80) {
        syscall_handler(regs);
        return;
    }

    /* Phase 18.5.6: vector 14 (page fault) is the only exception the CPU
     * hands us a faulting address for -- in CR2, never captured anywhere
     * in this codebase before. Checked first against the current thread's
     * kernel-stack guard page (kernel/scheduler.c) so an overflow gets a
     * specific diagnostic instead of a generic "Page fault" with no address
     * at all, which is what let the fs/fat32.c cbuf overflow (docs/SECURITY.md
     * "Step 18.5") go unnoticed until it corrupted unrelated heap memory. */
    if (regs->int_no == 14) {
        uint32_t cr2;
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
        if (thread_kstack_guard_hit(thread_current(), cr2))
            kprintf("\n*** KERNEL STACK OVERFLOW: fault addr=0x%x eip=0x%x (guard page)\n",
                    cr2, regs->eip);
        else
            kprintf("\n*** PAGE FAULT: fault addr=0x%x err=%u eip=0x%x\n",
                    cr2, regs->err_code, regs->eip);
        kprintf("*** System halted.\n");
        for (;;)
            __asm__ volatile("cli; hlt");
    }

    const char *msg = regs->int_no < 32 ? exception_messages[regs->int_no]
                                        : "Unknown";
    kprintf("\n*** CPU EXCEPTION: %s (int=%u err=%u eip=0x%x)\n",
            msg, regs->int_no, regs->err_code, regs->eip);
    kprintf("*** System halted.\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* Called from the assembly stub for hardware IRQs (vectors 32-47). */
void irq_handler(registers_t *regs)
{
    /* Send end-of-interrupt to the slave PIC if this came from IRQ 8-15. */
    if (regs->int_no >= 40)
        outb(0xA0, 0x20);
    outb(0x20, 0x20);   /* and always to the master PIC */

    isr_t handler = handlers[regs->int_no];
    if (handler)
        handler(regs);
}
