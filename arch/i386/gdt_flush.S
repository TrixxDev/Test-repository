/* void gdt_flush(uint32_t gdt_ptr)
 * Loads the GDT described by gdt_ptr and reloads all segment registers.
 * The far jump reloads CS with the new kernel code selector (0x08). */
.section .text
.global gdt_flush
.type gdt_flush, @function
gdt_flush:
    movl 4(%esp), %eax
    lgdt (%eax)

    movw $0x10, %ax          /* 0x10 = kernel data segment */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    ljmp $0x08, $.flush      /* 0x08 = kernel code segment */
.flush:
    ret
.size gdt_flush, . - gdt_flush
