/* AuroraOS kernel linker script (i686, Multiboot1).
 * The kernel is loaded at the conventional 1 MiB mark. The .multiboot
 * section is placed first so the bootloader (or `qemu -kernel`) finds the
 * Multiboot header within the first 8 KiB of the image. */
ENTRY(_start)

SECTIONS
{
    . = 1M;
    kernel_start = .;

    .text ALIGN(4096) :
    {
        *(.multiboot)
        *(.text)
    }

    .rodata ALIGN(4096) :
    {
        *(.rodata)
    }

    .data ALIGN(4096) :
    {
        *(.data)
    }

    .bss ALIGN(4096) :
    {
        *(COMMON)
        *(.bss)
    }

    kernel_end = .;
}
