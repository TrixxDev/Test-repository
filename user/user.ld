/* Link map for AuroraOS user programs. Loaded at 4 GiB/16... no: at 0x40000000,
 * comfortably inside the user half of the address space. */
ENTRY(_start)

SECTIONS
{
    . = 0x40000000;

    .text   : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data   : { *(.data*) }
    .bss    : { *(.bss*) *(COMMON) }
}
