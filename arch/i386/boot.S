/* Multiboot1 header and kernel entry point.
 *
 * The bootloader hands control to _start in 32-bit protected mode with paging
 * disabled and an undefined stack. We set up our own stack, then call into the
 * C kernel, passing along the Multiboot magic value and info structure. */

.set MB_ALIGN,    1 << 0              /* align loaded modules on page boundaries */
.set MB_MEMINFO,  1 << 1              /* provide a memory map */
.set MB_VIDEO,    1 << 2              /* request a video (framebuffer) mode */
.set MB_FLAGS,    MB_ALIGN | MB_MEMINFO | MB_VIDEO
.set MB_MAGIC,    0x1BADB002          /* magic the bootloader looks for */
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

.section .multiboot, "a"
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM
.long 0, 0, 0, 0, 0                   /* a.out kludge fields (unused: ELF) */
.long 0                              /* mode_type: 0 = linear graphics */
.long 1024                          /* preferred width  */
.long 768                           /* preferred height */
.long 32                            /* preferred depth (bpp) */

.section .bss, "aw", @nobits
.align 16
stack_bottom:
.skip 16384                           /* 16 KiB kernel stack */
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    movl $stack_top, %esp             /* set up the stack */

    pushl %ebx                        /* arg2: pointer to Multiboot info */
    pushl %eax                        /* arg1: Multiboot magic (0x2BADB002) */
    call kernel_main

    cli                               /* should never return; if it does, hang */
.Lhang:
    hlt
    jmp .Lhang
.size _start, . - _start
