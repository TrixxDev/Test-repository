#include "syscall.h"
#include "kio.h"
#include "scheduler.h"
#include "process.h"

/* Convention: eax = syscall number, ebx/ecx/edx = arguments. The return value
 * is written back into regs->eax (restored to the user's eax by the stub). */
void syscall_handler(registers_t *regs)
{
    switch (regs->eax) {
    case SYS_PUTC:
        kputchar((char)regs->ebx);
        regs->eax = 0;
        break;

    case SYS_YIELD:
        schedule();
        regs->eax = 0;
        break;

    case SYS_EXIT:
        process_exit((int)regs->ebx);   /* never returns */
        break;

    case SYS_FORK:
        regs->eax = (uint32_t)do_fork(regs);
        break;

    case SYS_EXEC:
        do_exec((const char *)regs->ebx, (char **)regs->ecx, regs);  /* no return on success */
        break;

    case SYS_WAIT:
        regs->eax = (uint32_t)process_wait(-1, (int *)regs->ebx, (int)regs->ecx);
        break;

    case SYS_OPEN:
        regs->eax = (uint32_t)sys_open((const char *)regs->ebx, (int)regs->ecx);
        break;

    case SYS_READ:
        regs->eax = (uint32_t)sys_read((int)regs->ebx, (void *)regs->ecx, regs->edx);
        break;

    case SYS_WRITE:
        regs->eax = (uint32_t)sys_write((int)regs->ebx, (const void *)regs->ecx, regs->edx);
        break;

    case SYS_CLOSE:
        regs->eax = (uint32_t)sys_close((int)regs->ebx);
        break;

    case SYS_GETPID:
        regs->eax = (uint32_t)process_current()->pid;
        break;

    case SYS_PIPE:
        regs->eax = (uint32_t)sys_pipe((int *)regs->ebx);
        break;

    case SYS_DUP2:
        regs->eax = (uint32_t)sys_dup2((int)regs->ebx, (int)regs->ecx);
        break;

    case SYS_SBRK:
        regs->eax = sys_sbrk((int)regs->ebx);
        break;

    case SYS_MSGSEND:
        regs->eax = (uint32_t)sys_msgsend((int)regs->ebx, (const void *)regs->ecx, (int)regs->edx);
        break;

    case SYS_MSGRECV:
        regs->eax = (uint32_t)sys_msgrecv((void *)regs->ebx, (int)regs->ecx, (int *)regs->edx);
        break;

    case SYS_REGISTER:
        regs->eax = (uint32_t)sys_register((const char *)regs->ebx);
        break;

    case SYS_LOOKUP:
        regs->eax = (uint32_t)sys_lookup((const char *)regs->ebx);
        break;

    case SYS_KILL:
        regs->eax = (uint32_t)sys_kill((int)regs->ebx);
        break;

    default:
        kprintf("\n[syscall] unknown call %u\n", regs->eax);
        regs->eax = (uint32_t)-1;
        break;
    }
}
