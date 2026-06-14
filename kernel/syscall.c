#include "syscall.h"
#include "kio.h"
#include "scheduler.h"

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
        /* Terminate the calling thread and hand the CPU to another. */
        thread_exit();
        break;
    default:
        kprintf("\n[syscall] unknown call %u\n", regs->eax);
        break;
    }
}
