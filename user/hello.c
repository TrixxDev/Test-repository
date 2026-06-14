/* A tiny ring-3 user program for AuroraOS.
 *
 * Built as a separate freestanding ELF (see user/user.ld) and loaded by the
 * kernel's ELF loader into its own address space. Talks to the kernel only
 * through the int 0x80 system call interface. */

#define SYS_PUTC  1
#define SYS_YIELD 2
#define SYS_EXIT  3

static int syscall(int num, int arg)
{
    int ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(num), "b"(arg));
    return ret;
}

static void uputs(const char *s)
{
    while (*s)
        syscall(SYS_PUTC, *s++);
}

void _start(void)
{
    uputs("  >> Hello from a userspace ELF running in ring 3!\n");

    for (int i = 0; i < 3; i++) {
        uputs("  >> user process: doing work...\n");
        for (volatile int d = 0; d < 4000000; d++)
            ;
        syscall(SYS_YIELD, 0);
    }

    uputs("  >> user process: exiting via SYS_EXIT.\n");
    syscall(SYS_EXIT, 0);

    for (;;)
        ;
}
