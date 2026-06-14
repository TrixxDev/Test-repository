/* AuroraOS kernel entry point.
 *
 * Stage 3 bring-up: a Unix-like process model. The kernel starts an init
 * process from disk; init fork()s, the child exec()s another program, and init
 * wait()s for it, reaping its exit code. The kernel finally reaps init. */
#include <stdint.h>

#include "kio.h"
#include "multiboot.h"
#include "gdt.h"
#include "idt.h"
#include "isr.h"
#include "serial.h"
#include "pit.h"
#include "keyboard.h"
#include "pmm.h"
#include "paging.h"
#include "kheap.h"
#include "scheduler.h"
#include "process.h"
#include "vfs.h"
#include "tmpfs.h"
#include "fat32.h"
#include "ata.h"

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

/* init, embedded as a fallback if no disk is present. */
extern const unsigned char user_elf[];
extern const unsigned int  user_elf_len;

static void banner(void)
{
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    terminal_writestring(
        "    _                          \n"
        "   /_\\  _  _ _ _ ___ _ _ __ _  \n"
        "  / _ \\| || | '_/ _ \\ '_/ _` | \n"
        " /_/ \\_\\\\_,_|_| \\___/_| \\__,_| \n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);
    terminal_writestring("        AuroraOS  v0.4.0  (processes: fork/exec/wait)\n\n");
}

void kernel_main(uint32_t magic, uint32_t mb_info)
{
    serial_init();
    terminal_initialize();
    banner();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        kprintf("[warn] unexpected multiboot magic: 0x%x\n", magic);

    const multiboot_info_t *mb = (const multiboot_info_t *)mb_info;

    kprintf("[boot] GDT + TSS, IDT, interrupts, syscalls...\n");
    gdt_install();
    idt_install();
    isr_install();
    pit_install(100);
    keyboard_install();

    kprintf("[boot] physical memory...\n");
    pmm_init(mb);
    kprintf("      %u MiB usable (%u frames free)\n",
            pmm_total_frames() * 4 / 1024, pmm_free_frames());

    kprintf("[boot] paging + kernel heap...\n");
    paging_init();
    kheap_init();

    kprintf("[boot] VFS + tmpfs...\n");
    vfs_init();
    vfs_mount("/tmp", tmpfs_create());

    /* tmpfs fallback copy of init. */
    vfs_node_t *tmp = vfs_resolve("/tmp");
    vfs_node_t *fb = vfs_create(tmp, "init.elf", VFS_FILE);
    vfs_write(fb, 0, user_elf_len, user_elf);

    const char *init_path = "/tmp/init.elf";
    kprintf("[boot] probing ATA disk...\n");
    if (ata_init()) {
        vfs_node_t *root = fat32_mount();
        if (root) {
            vfs_mount("/disk", root);
            kprintf("      FAT32 mounted at /disk:\n");
            char name[64];
            for (uint32_t i = 0; vfs_readdir(root, i, name, sizeof(name)) == 0; i++)
                kprintf("        /disk/%s\n", name);
            if (vfs_resolve("/disk/INIT.ELF"))
                init_path = "/disk/INIT.ELF";
        }
    } else {
        kprintf("      no ATA disk; using embedded init\n");
    }

    __asm__ volatile("sti");

    kprintf("[boot] scheduler + process model...\n");
    scheduler_init();
    process_init();         /* pid 0 = kernel, bound to this thread */

    /* Load and start init. */
    vfs_node_t *f = vfs_resolve(init_path);
    uint8_t *buf = (uint8_t *)kmalloc(f->size);
    vfs_read(f, 0, f->size, buf);

    terminal_setcolor(VGA_LIGHT_GREEN, VGA_BLACK);
    kprintf("\n[exec] starting init from %s\n\n", init_path);
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    int initpid = process_spawn(buf, f->size);
    kfree(buf);

    scheduler_enable();

    /* The kernel reaps init when it exits (demonstrates wait/cleanup). */
    int status = -1;
    int reaped = process_wait(initpid, &status);

    scheduler_disable();
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    kprintf("\n[kernel] reaped init (pid %d), exit code %d. System idle.\n",
            reaped, status);
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    for (;;)
        __asm__ volatile("hlt");
}
