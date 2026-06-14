/* AuroraOS kernel entry point.
 *
 * Stage 1 bring-up: parse the memory map, initialise physical/virtual memory
 * and the kernel heap, then demonstrate the scheduler (kernel threads) and a
 * ring 3 user program talking to the kernel via system calls. */
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

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

extern void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top);
extern uint8_t user_program[];
extern uint8_t user_program_end[];

static void banner(void)
{
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    terminal_writestring(
        "    _                          \n"
        "   /_\\  _  _ _ _ ___ _ _ __ _  \n"
        "  / _ \\| || | '_/ _ \\ '_/ _` | \n"
        " /_/ \\_\\\\_,_|_| \\___/_| \\__,_| \n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);
    terminal_writestring("        AuroraOS  v0.2.0  (memory + multitasking)\n\n");
}

static void print_memory_map(const multiboot_info_t *mb)
{
    if (!(mb->flags & MULTIBOOT_FLAG_MMAP)) {
        kprintf("[mem] no memory map provided by bootloader\n");
        return;
    }

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

/* ---- scheduler demo: two preemptively-scheduled kernel threads ---- */

static volatile int workers_active;

static void busy_delay(void)
{
    for (volatile uint32_t i = 0; i < 6000000; i++)
        ;
}

static void thread_a(void)
{
    for (int i = 0; i < 4; i++) {
        kprintf("    [thread A] step %d (ticks=%u)\n", i, pit_ticks());
        busy_delay();
    }
    kprintf("    [thread A] finished\n");
    workers_active--;
    task_exit();
}

static void thread_b(void)
{
    for (int i = 0; i < 4; i++) {
        kprintf("    [thread B] step %d (ticks=%u)\n", i, pit_ticks());
        busy_delay();
    }
    kprintf("    [thread B] finished\n");
    workers_active--;
    task_exit();
}

/* ---- ring 3 demo ---- */

static void usermode_demo(void)
{
    const uint32_t code_v  = 0x40000000;
    const uint32_t stack_v = 0x40100000;

    vmm_map_page(code_v,  pmm_alloc_frame(), PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
    vmm_map_page(stack_v, pmm_alloc_frame(), PAGE_PRESENT | PAGE_WRITE | PAGE_USER);

    uint32_t len = (uint32_t)(user_program_end - user_program);
    for (uint32_t i = 0; i < len; i++)
        ((uint8_t *)code_v)[i] = user_program[i];

    kprintf("[user] entering ring 3...\n");
    enter_user_mode(code_v, stack_v + PAGE_SIZE);
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

    /* Quick heap sanity check. */
    void *a = kmalloc(128);
    void *b = kmalloc(4096);
    kprintf("      kmalloc(128)=%p kmalloc(4096)=%p used=%u bytes\n",
            a, b, (uint32_t)kheap_used());
    kfree(a);
    kfree(b);
    kprintf("      after free: used=%u bytes\n", (uint32_t)kheap_used());

    __asm__ volatile("sti");

    /* --- multitasking demo --- */
    terminal_setcolor(VGA_LIGHT_GREEN, VGA_BLACK);
    kprintf("\n[sched] launching two kernel threads:\n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    workers_active = 2;
    scheduler_init();
    task_create(thread_a);
    task_create(thread_b);
    scheduler_enable();

    while (workers_active > 0)
        __asm__ volatile("hlt");

    scheduler_disable();
    kprintf("[sched] all threads done.\n\n");

    /* --- ring 3 demo --- */
    terminal_setcolor(VGA_LIGHT_MAGENTA, VGA_BLACK);
    usermode_demo();

    /* usermode_demo never returns; stay responsive just in case. */
    for (;;)
        __asm__ volatile("hlt");
}
