/* AuroraOS kernel entry point.
 *
 * Stage 4 bring-up: the kernel starts an interactive shell as the first user
 * process. The shell reads commands from stdin and fork()/exec()s programs from
 * /disk. The kernel reaps the shell when it exits. */
#include <stdint.h>

#include "kio.h"
#include "multiboot.h"
#include "gdt.h"
#include "idt.h"
#include "isr.h"
#include "serial.h"
#include "pit.h"
#include "perf.h"
#include "virtio_net.h"
#include "netstack.h"
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
#include "fb.h"
#include "mouse.h"

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

/* Always-runnable thread: keeps the CPU alive (interrupts on) when every other
 * thread is blocked, so device IRQs can still wake them. */
static void idle_thread(void)
{
    for (;;)
        __asm__ volatile("sti; hlt");
}

/* init, embedded as a fallback if no disk is present. */
extern const unsigned char user_elf[];
extern const unsigned int  user_elf_len;

/* True if `word` appears in the (space-separated) Multiboot command line. */
static int cmdline_has_word(const multiboot_info_t *mb, const char *word)
{
    if (!(mb->flags & MULTIBOOT_FLAG_CMDLINE) || !mb->cmdline)
        return 0;
    for (const char *cl = (const char *)mb->cmdline; *cl; cl++) {
        const char *a = cl, *b = word;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b)
            return 1;
    }
    return 0;
}

static void banner(void)
{
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    terminal_writestring(
        "    _                          \n"
        "   /_\\  _  _ _ _ ___ _ _ __ _  \n"
        "  / _ \\| || | '_/ _ \\ '_/ _` | \n"
        " /_/ \\_\\\\_,_|_| \\___/_| \\__,_| \n");
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);
    terminal_writestring("        AuroraOS  v1.1.2  (Settings)\n\n");
}

void kernel_main(uint32_t magic, uint32_t mb_info)
{
    serial_init();
    terminal_initialize();
    banner();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        kprintf("[warn] unexpected multiboot magic: 0x%x\n", magic);

    const multiboot_info_t *mb = (const multiboot_info_t *)mb_info;

    /* Each step logs before it runs, so if an early fault triple-faults and
     * resets the machine, the last serial line names the exact failing step. */
    kprintf("[boot] GDT + TSS...\n");      gdt_install();
    kprintf("[boot] IDT...\n");            idt_install();
    kprintf("[boot] interrupts...\n");     isr_install();
    kprintf("[boot] PIT timer...\n");      pit_install(100);
    kprintf("[boot] keyboard...\n");       keyboard_install();
    kprintf("[boot] PS/2 mouse...\n");     mouse_install(cmdline_has_word(mb, "abs"));

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

    kprintf("[boot] graphics...\n");
    if (fb_init(mb))
        kprintf("      linear framebuffer up; drawing desktop\n");
    else
        kprintf("      no framebuffer from loader; staying in text mode\n");

    __asm__ volatile("sti");

    kprintf("[boot] calibrating timer...\n");
    perf_calibrate();       /* PIT is live, scheduler not yet hooked: clean window */

    kprintf("[boot] probing network...\n");
    virtio_net_init();      /* PCI scan for virtio-net (no-op if absent) */
    net_init();             /* ARP cache + protocol layers */
    net_selftest();         /* Phase 4/5 proof: Ethernet + ARP (no-op if absent) */

    kprintf("[boot] scheduler + process model...\n");
    scheduler_init();
    process_init();         /* pid 0 = kernel, bound to this thread */

    /* Load and start init. */
    vfs_node_t *f = vfs_resolve(init_path);
    uint8_t *buf = (uint8_t *)kmalloc(f->size);
    vfs_read(f, 0, f->size, buf);

    terminal_setcolor(VGA_LIGHT_GREEN, VGA_BLACK);
    kprintf("\n[exec] starting init from %s\n", init_path);
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    int initpid = process_spawn(buf, f->size, "init");
    kfree(buf);

    /* Frame consistency: only the userspace windowserver writes the framebuffer.
     * (It is started by init in graphics mode and paints the desktop itself.) */

    thread_create_kernel(idle_thread);  /* always-runnable fallback */

    scheduler_enable();

    /* The kernel reaps init when it exits (demonstrates wait/cleanup). */
    int status = -1;
    int reaped = process_wait(initpid, &status, 0);

    scheduler_disable();
    terminal_setcolor(VGA_LIGHT_CYAN, VGA_BLACK);
    kprintf("\n[kernel] init (pid %d) exited with code %d. System idle.\n",
            reaped, status);
    terminal_setcolor(VGA_LIGHT_GREY, VGA_BLACK);

    for (;;)
        __asm__ volatile("hlt");
}
