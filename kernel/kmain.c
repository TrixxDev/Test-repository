/* AuroraOS kernel entry point.
 *
 * Called from boot.S after the stack is set up. Brings the core subsystems
 * online, prints a banner, then idles while interrupts drive the system
 * (keyboard input is echoed by the keyboard driver). */
#include <stdint.h>

#include "kio.h"
#include "gdt.h"
#include "idt.h"
#include "isr.h"
#include "serial.h"
#include "pit.h"
#include "keyboard.h"

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

static void banner(void)
{
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    terminal_writestring(
        "    _                          \n"
        "   /_\\  _  _ _ _ ___ _ _ __ _  \n"
        "  / _ \\| || | '_/ _ \\ '_/ _` | \n"
        " /_/ \\_\\\\_,_|_| \\___/_| \\__,_| \n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);
    terminal_writestring("        AuroraOS  v0.1.0\n\n");
}

void kernel_main(uint32_t magic, uint32_t mb_info)
{
    (void)mb_info;

    serial_init();
    terminal_initialize();

    banner();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        kprintf("[warn] unexpected multiboot magic: 0x%x\n", magic);

    kprintf("[boot] installing GDT...\n");
    gdt_install();

    kprintf("[boot] installing IDT...\n");
    idt_install();

    kprintf("[boot] installing interrupt handlers + remapping PIC...\n");
    isr_install();

    kprintf("[boot] starting timer (100 Hz)...\n");
    pit_install(100);

    kprintf("[boot] enabling keyboard...\n");
    keyboard_install();

    __asm__ volatile("sti");            /* enable interrupts */

    terminal_setcolor(VGA_LIGHT_GREEN, VGA_BLACK);
    kprintf("\n[ok] AuroraOS is up. Type something:\n\n");
    terminal_setcolor(VGA_WHITE, VGA_BLACK);
    kprintf("> ");

    for (;;)
        __asm__ volatile("hlt");        /* sleep until the next interrupt */
}
