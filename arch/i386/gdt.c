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

/* null, kernel code, kernel data, user code, user data, TSS. */
static struct gdt_entry gdt[6];
static struct gdt_ptr   gp;
static struct tss_entry tss;

/* Dedicated ring-0 stack used when handling interrupts that arrive from ring 3. */
static uint8_t kernel_stack[16384] __attribute__((aligned(16)));

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

    gdt_flush((uint32_t)&gp);

    __asm__ volatile("ltr %%ax" : : "a"((uint16_t)0x28));  /* TSS selector */
}
