/* Interrupt stubs.
 *
 * The CPU pushes an error code only for some exceptions; for the rest we push a
 * dummy 0 so the stack layout (and therefore registers_t) is uniform. Each stub
 * pushes its vector number and jumps to a common handler that saves the full
 * register state, calls into C, then restores and returns with iret. */

.set KERNEL_DATA_SEG, 0x10

/* Exception with no CPU-pushed error code. */
.macro ISR_NOERR num
    .global isr\num
    .type isr\num, @function
isr\num:
    cli
    pushl $0
    pushl $\num
    jmp isr_common_stub
.endm

/* Exception where the CPU already pushed an error code. */
.macro ISR_ERR num
    .global isr\num
    .type isr\num, @function
isr\num:
    cli
    pushl $\num
    jmp isr_common_stub
.endm

/* Hardware IRQ: vec is the remapped interrupt vector (32-47). */
.macro IRQ num, vec
    .global irq\num
    .type irq\num, @function
irq\num:
    cli
    pushl $0
    pushl $\vec
    jmp irq_common_stub
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_ERR   30
ISR_NOERR 31

ISR_NOERR 128                   /* system call vector (int 0x80) */

IRQ 0, 32
IRQ 1, 33
IRQ 2, 34
IRQ 3, 35
IRQ 4, 36
IRQ 5, 37
IRQ 6, 38
IRQ 7, 39
IRQ 8, 40
IRQ 9, 41
IRQ 10, 42
IRQ 11, 43
IRQ 12, 44
IRQ 13, 45
IRQ 14, 46
IRQ 15, 47

.extern isr_handler
isr_common_stub:
    pusha                       /* edi, esi, ebp, esp, ebx, edx, ecx, eax */
    movw %ds, %ax
    pushl %eax                  /* save data segment */

    movw $KERNEL_DATA_SEG, %ax  /* switch to kernel data segments */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushl %esp                  /* pass registers_t* to the handler */
    call isr_handler
    addl $4, %esp               /* drop the pointer argument */

    popl %eax                   /* restore data segment */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    popa
    addl $8, %esp               /* drop pushed err_code and int_no */
    sti
    iret

.extern irq_handler
irq_common_stub:
    pusha
    movw %ds, %ax
    pushl %eax

    movw $KERNEL_DATA_SEG, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    pushl %esp
    call irq_handler
    addl $4, %esp

    popl %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    popa
    addl $8, %esp
    sti
    iret
