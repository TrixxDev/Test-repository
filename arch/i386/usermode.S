/* Ring 3 entry plus a tiny position-independent user program. */

/* void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top)
 * Switches to ring 3 by building an iret frame with user selectors. */
.section .text
.global enter_user_mode
.type enter_user_mode, @function
enter_user_mode:
    movl 4(%esp), %ecx          /* entry EIP */
    movl 8(%esp), %edx          /* user stack top */

    movw $0x23, %ax             /* user data selector (0x20 | RPL 3) */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushl $0x23                 /* user SS */
    pushl %edx                  /* user ESP */
    pushfl                      /* EFLAGS ... */
    popl %eax
    orl $0x200, %eax            /* ... with interrupts enabled */
    pushl %eax
    pushl $0x1B                 /* user CS (0x18 | RPL 3) */
    pushl %ecx                  /* entry EIP */
    iret

/* A minimal ring 3 program: prints "RING3 alive" via syscalls, then loops
 * forever issuing yields. Uses only immediates + int, so it is position
 * independent and safe to copy into a user page. */
.global user_program
.global user_program_end
user_program:
    movl $1, %eax               /* SYS_PUTC */
    movl $'R', %ebx
    int $0x80
    movl $'I', %ebx
    int $0x80
    movl $'N', %ebx
    int $0x80
    movl $'G', %ebx
    int $0x80
    movl $'3', %ebx
    int $0x80
    movl $' ', %ebx
    int $0x80
    movl $'a', %ebx
    int $0x80
    movl $'l', %ebx
    int $0x80
    movl $'i', %ebx
    int $0x80
    movl $'v', %ebx
    int $0x80
    movl $'e', %ebx
    int $0x80
    movl $'\n', %ebx
    int $0x80
1:
    movl $2, %eax               /* SYS_YIELD */
    int $0x80
    jmp 1b
user_program_end:
