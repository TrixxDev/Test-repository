#include "syscall.h"
#include "kio.h"
#include "scheduler.h"
#include "process.h"
#include "socket.h"
#include "fb.h"
#include "mouse.h"
#include "io.h"
#include "shm.h"
#include "perf.h"

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

    case SYS_FCNTL:
        regs->eax = (uint32_t)sys_fcntl((int)regs->ebx, (int)regs->ecx, (int)regs->edx);
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
        regs->eax = (uint32_t)sys_register((const char *)regs->ebx, (uint32_t)regs->ecx);
        break;

    case SYS_LOOKUP:
        regs->eax = (uint32_t)sys_lookup((const char *)regs->ebx);
        break;

    case SYS_KILL:
        regs->eax = (uint32_t)sys_kill((int)regs->ebx);
        break;

    case SYS_SOCKET:
        regs->eax = (uint32_t)sys_socket((int)regs->ebx, (int)regs->ecx);
        break;

    case SYS_SOCK_LINK:
        /* Privileged broker primitive: only root (netd) may join endpoints. */
        if (process_current()->uid != 0)
            regs->eax = (uint32_t)-1;
        else
            regs->eax = (uint32_t)sock_link((uint32_t)regs->ebx, (uint32_t)regs->ecx);
        break;

    case SYS_POLL:
        regs->eax = (uint32_t)sys_poll((struct pollfd *)regs->ebx, (int)regs->ecx, (int)regs->edx);
        break;

    case SYS_GETUID:
        regs->eax = (uint32_t)sys_getuid();
        break;

    case SYS_SETUID:
        regs->eax = (uint32_t)sys_setuid((int)regs->ebx);
        break;

    case SYS_UIDOF:
        regs->eax = (uint32_t)sys_uid_of((int)regs->ebx);
        break;

    case SYS_FBMAP: {
        uint32_t *info = (uint32_t *)regs->ebx;     /* user [w, h, pitch] */
        uint32_t w = 0, h = 0, p = 0;
        uint32_t va = fb_user_map(&w, &h, &p);
        if (va && info) { info[0] = w; info[1] = h; info[2] = p; }
        regs->eax = va;
        break;
    }

    case SYS_FBACTIVE:
        regs->eax = (uint32_t)fb_is_active();
        break;

    case SYS_MOUSE: {
        int *out = (int *)regs->ebx;        /* user [x, y, buttons, absolute] */
        int x = 0, y = 0, btn = 0, abs = 0;
        mouse_get(&x, &y, &btn, &abs);      /* blocks until a packet arrives */
        if (out) { out[0] = x; out[1] = y; out[2] = btn; out[3] = abs; }
        regs->eax = 0;
        break;
    }

    case SYS_READDIR:
        regs->eax = (uint32_t)sys_readdir((const char *)regs->ebx, (int)regs->ecx,
                                          (struct dirent *)regs->edx);
        break;

    case SYS_SYSINFO:
        regs->eax = (uint32_t)sys_sysinfo((struct sysinfo *)regs->ebx);
        break;

    case SYS_SLEEP:
        regs->eax = (uint32_t)sys_sleep((int)regs->ebx);
        break;

    case SYS_UISCALE:
        regs->eax = (uint32_t)sys_uiscale((int)regs->ebx);
        break;

    case SYS_FBMODE:
        if (process_current()->uid != 0) {      /* root only (the window server) */
            regs->eax = (uint32_t)-1;
            break;
        }
        regs->eax = (uint32_t)fb_set_mode((uint32_t)regs->ebx, (uint32_t)regs->ecx);
        break;

    case SYS_SHMGET:
        regs->eax = (uint32_t)shm_create((uint32_t)regs->ebx, (uint32_t)regs->ecx);
        break;

    case SYS_SHMMAP:
        regs->eax = shm_map((int)regs->ebx);
        break;

    case SYS_SHMUNMAP:
        regs->eax = (uint32_t)shm_unmap((int)regs->ebx);
        break;

    case SYS_SHMGRANT:
        regs->eax = (uint32_t)shm_grant((int)regs->ebx, (int)regs->ecx);
        break;

    case SYS_PERFUS:
        regs->eax = (uint32_t)perf_now_us();    /* low 32 bits: ~71 min before wrap */
        break;

    case SYS_NETSTAT:
        regs->eax = (uint32_t)sys_netstat((struct net_stats *)regs->ebx);
        break;

    case SYS_TCPSTAT:
        regs->eax = (uint32_t)sys_tcpstat((struct tcp_stats *)regs->ebx);
        break;

    case SYS_HTTPGET:
        regs->eax = (uint32_t)sys_httpget((const char *)regs->ebx,
                                          (void *)regs->ecx, (int)regs->edx);
        break;

    case SYS_INET_CONNECT:
        regs->eax = (uint32_t)sys_inet_connect((int)regs->ebx,
                                               (const char *)regs->ecx, (int)regs->edx);
        break;

    case SYS_SHMDEL:
        regs->eax = (uint32_t)shm_destroy((int)regs->ebx);
        break;

    case SYS_HALT:
        if (process_current()->uid != 0) {      /* root only */
            regs->eax = (uint32_t)-1;
            break;
        }
        kprintf("\n[kernel] halt requested; powering off.\n");
        __asm__ volatile("cli");
        outw(0x604, 0x2000);                    /* QEMU/Bochs ACPI poweroff */
        outw(0xB004, 0x2000);                   /* older QEMU poweroff port */
        for (;;) __asm__ volatile("hlt");       /* fallback: stop the CPU    */
        break;

    default:
        kprintf("\n[syscall] unknown call %u\n", regs->eax);
        regs->eax = (uint32_t)-1;
        break;
    }
}
