#include "paging.h"
#include "pmm.h"

/* Identity-map this much low memory up front: enough to cover the kernel, the
 * PMM bitmap, the early page tables, and the VGA buffer. */
#define IDENTITY_SIZE (16u * 1024 * 1024)

/* With recursive mapping (PD entry 1023 points at the PD itself) the page
 * directory is visible at 0xFFFFF000 and each page table at this base. */
#define PD_VADDR  0xFFFFF000u
#define PT_VADDR(pdi) (0xFFC00000u + ((pdi) << 12))

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
