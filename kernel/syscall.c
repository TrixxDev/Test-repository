#include "syscall.h"
#include "kio.h"

/* Convention: eax = syscall number, ebx = first argument. */
void syscall_handler(registers_t *regs)
{
    switch (regs->eax) {
    case SYS_PUTC:
        kputchar((char)regs->ebx);
        break;
    case SYS_YIELD:
        /* Nothing to do here: the timer drives preemption. */
        break;
    case SYS_EXIT:
        /* A real OS would tear down the process; for now just stop the CPU
         * (interrupts stay on, so the rest of the system keeps running). */
        for (;;)
            __asm__ volatile("hlt");
        break;
    default:
        kprintf("\n[syscall] unknown call %u\n", regs->eax);
        break;
    }
}
