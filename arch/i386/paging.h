/* Virtual memory manager / paging (two-level, 4 KiB pages, recursive mapping). */
#pragma once
#include <stdint.h>

#define PAGE_PRESENT 0x1
#define PAGE_WRITE   0x2
#define PAGE_USER    0x4

/* Set up the kernel page directory, identity-map low memory, enable paging. */
void paging_init(void);

/* Map / unmap a single 4 KiB page in the current address space. */
void vmm_map_page(uint32_t virt, uint32_t phys, uint32_t flags);
void vmm_unmap_page(uint32_t virt);

/* Translate a virtual address to physical (0 if unmapped). */
uint32_t vmm_get_physical(uint32_t virt);
