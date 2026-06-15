/* C runtime startup for AuroraOS user programs.
 *
 * The kernel sets up the user stack as:  [esp] = argc, [esp+4] = argv[0], ...
 * crt0 turns that into a normal main(argc, argv) call and exits with its
 * return value via the SYS_EXIT system call. */
.section .text
.global _start
_start:
    movl (%esp), %eax        /* argc */
    leal 4(%esp), %edx       /* argv */
    pushl %edx
    pushl %eax
    call main
    addl $8, %esp

    /* exit(main_ret) */
    movl %eax, %ebx
    movl $3, %eax            /* SYS_EXIT */
    int $0x80
1:  jmp 1b
