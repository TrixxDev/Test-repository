#include <stdint.h>
#include "gdt.h"
#include "string.h"

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

/* Task State Segment. Only ss0/esp0 matter for us: the CPU loads them when an
 * interrupt transfers control from ring 3 to ring 0. */
struct tss_entry {
    uint32_t prev_tss;
    uint32_t esp0, ss0;
    uint32_t esp1, ss1;
    uint32_t esp2, ss2;
    uint32_t cr3, eip, eflags;
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t es, cs, ss, ds, fs, gs;
    uint32_t ldt;
    uint16_t trap, iomap_base;
} __attribute__((packed));

/* null, kernel code, kernel data, user code, user data, TSS, double-fault TSS. */
static struct gdt_entry gdt[7];
static struct gdt_ptr   gp;
static struct tss_entry tss;

/* Dedicated ring-0 stack used when handling interrupts that arrive from ring 3. */
static uint8_t kernel_stack[16384] __attribute__((aligned(16)));

/* Phase 18.5.6: the #DF task-gate target -- see gdt.h's DF_TSS_SELECTOR
 * comment. Its own small stack, entirely separate from every thread's own
 * (possibly just-overflowed) kernel stack. */
static struct tss_entry df_tss;
static uint8_t df_stack[4096] __attribute__((aligned(16)));
extern void df_handler_entry(void);   /* arch/i386/isr.c */

extern void gdt_flush(uint32_t gdt_ptr);

static void set_gate(int n, uint32_t base, uint32_t limit,
                     uint8_t access, uint8_t gran)
{
    gdt[n].base_low    = base & 0xFFFF;
    gdt[n].base_mid    = (base >> 16) & 0xFF;
    gdt[n].base_high   = (base >> 24) & 0xFF;
    gdt[n].limit_low   = limit & 0xFFFF;
    gdt[n].granularity = ((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[n].access      = access;
}

static void write_tss(int n)
{
    uint32_t base  = (uint32_t)&tss;
    uint32_t limit = sizeof(tss) - 1;

    set_gate(n, base, limit, 0x89, 0x00);   /* present, 32-bit TSS (available) */

    memset(&tss, 0, sizeof(tss));
    tss.ss0  = 0x10;                                  /* kernel data segment */
    tss.esp0 = (uint32_t)(kernel_stack + sizeof(kernel_stack));
    tss.iomap_base = sizeof(tss);
}

void tss_set_kernel_stack(uint32_t esp0)
{
    tss.esp0 = esp0;
}

/* Phase 18.5.6: see gdt.h's DF_TSS_SELECTOR comment. cr3 is left 0 here --
 * gdt_install() runs before paging_init(), so there's no meaningful value
 * yet; gdt_df_tss_set_cr3() patches it in once paging is up, well before
 * any thread (and so any guard page) exists. */
static void write_df_tss(int n)
{
    uint32_t base  = (uint32_t)&df_tss;
    uint32_t limit = sizeof(df_tss) - 1;

    set_gate(n, base, limit, 0x89, 0x00);   /* present, 32-bit TSS (available) */

    memset(&df_tss, 0, sizeof(df_tss));
    df_tss.ss0    = 0x10;
    df_tss.esp0   = (uint32_t)(df_stack + sizeof(df_stack));
    df_tss.ss     = 0x10;                              /* stack the task gate actually runs on */
    df_tss.esp    = (uint32_t)(df_stack + sizeof(df_stack));
    df_tss.cs     = 0x08;
    df_tss.ds = df_tss.es = df_tss.fs = df_tss.gs = 0x10;
    df_tss.eip    = (uint32_t)df_handler_entry;
    df_tss.eflags = 0x00000002;                        /* reserved bit only; IF=0 */
    df_tss.iomap_base = sizeof(df_tss);
}

void gdt_df_tss_set_cr3(uint32_t cr3)
{
    df_tss.cr3 = cr3;
}

void gdt_get_last_fault_state(uint32_t *eip, uint32_t *esp)
{
    if (eip) *eip = tss.eip;
    if (esp) *esp = tss.esp;
}

void gdt_install(void)
{
    gp.limit = sizeof(gdt) - 1;
    gp.base  = (uint32_t)&gdt;

    set_gate(0, 0, 0, 0, 0);                      /* null segment */
    set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);       /* kernel code: ring 0 */
    set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);       /* kernel data: ring 0 */
    set_gate(3, 0, 0xFFFFFFFF, 0xFA, 0xCF);       /* user code:   ring 3 */
    set_gate(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);       /* user data:   ring 3 */
    write_tss(5);
    write_df_tss(6);

    gdt_flush((uint32_t)&gp);

    __asm__ volatile("ltr %%ax" : : "a"((uint16_t)0x28));  /* TSS selector */
}
