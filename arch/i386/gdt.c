#include <stdint.h>
#include "gdt.h"

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

/* Null, kernel code, kernel data, user code, user data. */
static struct gdt_entry gdt[5];
static struct gdt_ptr   gp;

/* Defined in gdt_flush.S: loads the GDT and reloads the segment registers. */
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

void gdt_install(void)
{
    gp.limit = sizeof(gdt) - 1;
    gp.base  = (uint32_t)&gdt;

    set_gate(0, 0, 0, 0, 0);                      /* null segment */
    set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);       /* kernel code: ring 0 */
    set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);       /* kernel data: ring 0 */
    set_gate(3, 0, 0xFFFFFFFF, 0xFA, 0xCF);       /* user code:   ring 3 */
    set_gate(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);       /* user data:   ring 3 */

    gdt_flush((uint32_t)&gp);
}
