/* AuroraOS kernel entry point.
 *
 * Stage 2 bring-up: a VFS with tmpfs, an ELF loader, and a process model where
 * each process owns an address space. The demo loads a real ELF program from
 * the filesystem and runs it in ring 3 alongside a kernel thread. */
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

/* The user program, embedded by the build (tools/bin2c.py). */
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
    terminal_writestring("        AuroraOS  v0.3.0  (VFS + ELF + processes)\n\n");
}

static void print_memory_map(const multiboot_info_t *mb)
{
    if (!(mb->flags & MULTIBOOT_FLAG_MMAP))
        return;
    kprintf("[mem] BIOS memory map:\n");
    uint32_t ptr = mb->mmap_addr;
    uint32_t end = mb->mmap_addr + mb->mmap_length;
    while (ptr < end) {
        const multiboot_mmap_entry_t *e = (const multiboot_mmap_entry_t *)ptr;
        kprintf("      base=0x%x len=0x%x %s\n",
                (uint32_t)e->addr, (uint32_t)e->len,
                e->type == MULTIBOOT_MEMORY_AVAILABLE ? "available" : "reserved");
        ptr += e->size + 4;
    }
}

/* A kernel thread that prints a few heartbeats and exits. */
static void heartbeat_thread(void)
{
    for (int i = 0; i < 4; i++) {
        kprintf("    [kthread] heartbeat %d (ticks=%u)\n", i, pit_ticks());
        for (volatile uint32_t d = 0; d < 5000000; d++)
            ;
    }
    kprintf("    [kthread] done\n");
    thread_exit();
}

void kernel_main(uint32_t magic, uint32_t mb_info)
{
    serial_init();
    terminal_initialize();
    banner();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        kprintf("[warn] unexpected multiboot magic: 0x%x\n", magic);

    const multiboot_info_t *mb = (const multiboot_info_t *)mb_info;

    kprintf("[boot] GDT + TSS...\n");
    gdt_install();
    kprintf("[boot] IDT...\n");
    idt_install();
    kprintf("[boot] interrupts + PIC + syscalls...\n");
    isr_install();
    kprintf("[boot] timer (100 Hz)...\n");
    pit_install(100);
    kprintf("[boot] keyboard...\n");
    keyboard_install();

    print_memory_map(mb);

    kprintf("[boot] physical memory manager...\n");
    pmm_init(mb);
    kprintf("      %u MiB usable, %u frames (%u free)\n",
            pmm_total_frames() * 4 / 1024, pmm_total_frames(), pmm_free_frames());

    kprintf("[boot] paging...\n");
    paging_init();
    kprintf("[boot] kernel heap...\n");
    kheap_init();

    kprintf("[boot] VFS + tmpfs...\n");
    vfs_init();
    vfs_mount("/tmp", tmpfs_create());

    /* Store the embedded program in tmpfs, proving the writable VFS pipeline. */
    vfs_node_t *tmp = vfs_resolve("/tmp");
    vfs_node_t *prog = vfs_create(tmp, "hello.elf", VFS_FILE);
    vfs_write(prog, 0, user_elf_len, user_elf);
    kprintf("      wrote /tmp/hello.elf (%u bytes)\n", user_elf_len);

    /* Mount the FAT32 disk (ATA) if present. */
    const char *exec_path = "/tmp/hello.elf";
    kprintf("[boot] probing ATA disk...\n");
    if (ata_init()) {
        vfs_node_t *fat_root = fat32_mount();
        if (fat_root) {
            vfs_mount("/disk", fat_root);
            kprintf("      FAT32 mounted at /disk; contents:\n");
            char name[64];
            for (uint32_t i = 0; vfs_readdir(fat_root, i, name, sizeof(name)) == 0; i++)
                kprintf("        /disk/%s\n", name);
            if (vfs_resolve("/disk/HELLO.ELF"))
                exec_path = "/disk/HELLO.ELF";
        } else {
            kprintf("      no FAT32 filesystem found\n");
        }
    } else {
        kprintf("      no ATA disk attached\n");
    }

    __asm__ volatile("sti");

    kprintf("[boot] scheduler...\n");
    scheduler_init();

    /* Load the program from the VFS and launch it as a process. */
    vfs_node_t *f = vfs_resolve(exec_path);
    uint8_t *buf = (uint8_t *)kmalloc(f->size);
    vfs_read(f, 0, f->size, buf);

    terminal_setcolor(VGA_LIGHT_GREEN, VGA_BLACK);
    kprintf("\n[exec] spawning ring-3 process from %s, plus a kernel thread:\n", exec_path);
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    int pid = process_spawn(buf, f->size);
    kprintf("[exec] process started (tid=%d)\n", pid);
    thread_create_kernel(heartbeat_thread);

    scheduler_enable();

    /* Wait until only this (main) thread remains. */
    while (thread_count() > 1)
        __asm__ volatile("hlt");

    scheduler_disable();
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    kprintf("\n[ok] process + thread finished. AuroraOS idle.\n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    for (;;)
        __asm__ volatile("hlt");
}
