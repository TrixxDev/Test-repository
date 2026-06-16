#include "paging.h"
#include "pmm.h"

/* Identity-map this much low memory up front: enough to cover the kernel, the
 * PMM bitmap, the early page tables, and the VGA buffer. */
#define IDENTITY_SIZE (16u * 1024 * 1024)

/* With recursive mapping (PD entry 1023 points at the PD itself) the page
 * directory is visible at 0xFFFFF000 and each page table at this base. */
#define PD_VADDR  0xFFFFF000u
#define PT_VADDR(pdi) (0xFFC00000u + ((pdi) << 12))

/* Scratch page used to edit a page directory that isn't currently loaded. */
#define TEMP_VADDR 0xCF000000u

static uint32_t kernel_pd_phys;

static inline void invlpg(uint32_t addr)
{
    __asm__ volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

/* Build a page table entry while paging is still off (physical == virtual). */
static void early_map(uint32_t *pd, uint32_t virt, uint32_t phys)
{
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;

    if (!(pd[pdi] & PAGE_PRESENT)) {
        uint32_t pt_frame = pmm_alloc_frame();
        uint32_t *pt = (uint32_t *)pt_frame;
        for (int i = 0; i < 1024; i++)
            pt[i] = 0;
        pd[pdi] = pt_frame | PAGE_PRESENT | PAGE_WRITE;
    }

    uint32_t *pt = (uint32_t *)(pd[pdi] & 0xFFFFF000);
    pt[pti] = (phys & 0xFFFFF000) | PAGE_PRESENT | PAGE_WRITE;
}

void paging_init(void)
{
    kernel_pd_phys = pmm_alloc_frame();
    uint32_t *pd = (uint32_t *)kernel_pd_phys;     /* paging off: identity access */
    for (int i = 0; i < 1024; i++)
        pd[i] = 0;

    /* Recursive mapping. */
    pd[1023] = kernel_pd_phys | PAGE_PRESENT | PAGE_WRITE;

    for (uint32_t a = 0; a < IDENTITY_SIZE; a += 0x1000)
        early_map(pd, a, a);

    /* Load CR3 and turn on paging (CR0.PG). */
    __asm__ volatile("mov %0, %%cr3" : : "r"(kernel_pd_phys));
    uint32_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000u;
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));
}

void vmm_map_page(uint32_t virt, uint32_t phys, uint32_t flags)
{
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;
    uint32_t *pd = (uint32_t *)PD_VADDR;
    uint32_t *pt = (uint32_t *)PT_VADDR(pdi);

    if (!(pd[pdi] & PAGE_PRESENT)) {
        uint32_t pt_frame = pmm_alloc_frame();
        /* Propagate USER so user pages in this table are reachable. */
        pd[pdi] = pt_frame | PAGE_PRESENT | PAGE_WRITE | (flags & PAGE_USER);
        invlpg((uint32_t)pt);
        for (int i = 0; i < 1024; i++)
            pt[i] = 0;
    }

    pt[pti] = (phys & 0xFFFFF000) | (flags & 0xFFF) | PAGE_PRESENT;
    invlpg(virt);
}

void vmm_unmap_page(uint32_t virt)
{
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;
    uint32_t *pd = (uint32_t *)PD_VADDR;
    uint32_t *pt = (uint32_t *)PT_VADDR(pdi);

    if (!(pd[pdi] & PAGE_PRESENT))
        return;

    pt[pti] = 0;
    invlpg(virt);
}

uint32_t vmm_get_physical(uint32_t virt)
{
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;
    uint32_t *pd = (uint32_t *)PD_VADDR;
    uint32_t *pt = (uint32_t *)PT_VADDR(pdi);

    if (!(pd[pdi] & PAGE_PRESENT))
        return 0;
    if (!(pt[pti] & PAGE_PRESENT))
        return 0;
    return (pt[pti] & 0xFFFFF000) | (virt & 0xFFF);
}

uint32_t vmm_kernel_directory(void) { return kernel_pd_phys; }

uint32_t vmm_current_directory(void)
{
    uint32_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3 & 0xFFFFF000;
}

void vmm_switch_address_space(uint32_t pd_phys)
{
    __asm__ volatile("mov %0, %%cr3" : : "r"(pd_phys) : "memory");
}

void vmm_ensure_table(uint32_t virt)
{
    uint32_t pdi = virt >> 22;
    uint32_t *pd = (uint32_t *)PD_VADDR;
    uint32_t *pt = (uint32_t *)PT_VADDR(pdi);

    if (!(pd[pdi] & PAGE_PRESENT)) {
        uint32_t frame = pmm_alloc_frame();
        pd[pdi] = frame | PAGE_PRESENT | PAGE_WRITE;
        invlpg((uint32_t)pt);
        for (int i = 0; i < 1024; i++)
            pt[i] = 0;
    }
}

void *vmm_temp_map(uint32_t phys)
{
    uint32_t *pt = (uint32_t *)PT_VADDR(TEMP_VADDR >> 22);
    pt[(TEMP_VADDR >> 12) & 0x3FF] = (phys & 0xFFFFF000) | PAGE_PRESENT | PAGE_WRITE;
    invlpg(TEMP_VADDR);
    return (void *)TEMP_VADDR;
}

void vmm_temp_unmap(void)
{
    uint32_t *pt = (uint32_t *)PT_VADDR(TEMP_VADDR >> 22);
    pt[(TEMP_VADDR >> 12) & 0x3FF] = 0;
    invlpg(TEMP_VADDR);
}

uint32_t vmm_create_address_space(void)
{
    uint32_t pd = pmm_alloc_frame();
    uint32_t *p = (uint32_t *)vmm_temp_map(pd);
    uint32_t *cur = (uint32_t *)PD_VADDR;

    for (int i = 0; i < 1024; i++)
        p[i] = 0;

    /* Share the kernel: low identity-mapped memory (indices 0-3) and all of
     * high memory at/above 0xC0000000 (heap, scratch table, etc.). */
    for (int i = 0; i < 4; i++)
        p[i] = cur[i];
    for (int i = 768; i < 1023; i++)
        p[i] = cur[i];

    /* Recursive entry points at this directory itself. */
    p[1023] = pd | PAGE_PRESENT | PAGE_WRITE;

    vmm_temp_unmap();
    return pd;
}

void vmm_destroy_address_space(uint32_t pd_phys)
{
    /* Snapshot the user PD entries (indices 256..767), since walking each page
     * table reuses the single scratch slot. */
    uint32_t pd_user[512];
    uint32_t *p = (uint32_t *)vmm_temp_map(pd_phys);
    for (int i = 0; i < 512; i++)
        pd_user[i] = p[256 + i];
    vmm_temp_unmap();

    for (int i = 0; i < 512; i++) {
        if (!(pd_user[i] & PAGE_PRESENT))
            continue;
        uint32_t pt_frame = pd_user[i] & 0xFFFFF000;
        uint32_t *pt = (uint32_t *)vmm_temp_map(pt_frame);
        for (int j = 0; j < 1024; j++)
            if (pt[j] & PAGE_PRESENT)
                pmm_free_frame(pt[j] & 0xFFFFF000);
        vmm_temp_unmap();
        pmm_free_frame(pt_frame);
    }

    pmm_free_frame(pd_phys);
}
