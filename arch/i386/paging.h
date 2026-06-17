/* Virtual memory manager / paging (two-level, 4 KiB pages, recursive mapping). */
#pragma once
#include <stdint.h>

#define PAGE_PRESENT 0x1
#define PAGE_WRITE   0x2
#define PAGE_USER    0x4
/* OS-available PTE bit (bit 9): marks a frame as shared memory owned by the SHM
 * subsystem, not by this address space. vmm_destroy_address_space unmaps but does
 * NOT free such frames, so tearing down one mapper never frees memory another
 * mapper (or the SHM owner) still uses. */
#define PAGE_SHARED  0x200

/* Set up the kernel page directory, identity-map low memory, enable paging. */
void paging_init(void);

/* Map / unmap a single 4 KiB page in the current address space. */
void vmm_map_page(uint32_t virt, uint32_t phys, uint32_t flags);
void vmm_unmap_page(uint32_t virt);

/* Translate a virtual address to physical (0 if unmapped). */
uint32_t vmm_get_physical(uint32_t virt);

/* --- multiple address spaces (per-process page directories) --- */

/* Physical address of the shared kernel page directory. */
uint32_t vmm_kernel_directory(void);

/* Physical address of the currently active page directory (CR3). */
uint32_t vmm_current_directory(void);

/* Create a new address space that shares the kernel mappings. Returns the
 * physical address of its page directory. */
uint32_t vmm_create_address_space(void);

/* Load `pd_phys` into CR3. */
void vmm_switch_address_space(uint32_t pd_phys);

/* Pre-create the page table backing `virt` (so it can be shared by reference). */
void vmm_ensure_table(uint32_t virt);

/* Temporarily map a physical frame to a scratch virtual page (for editing an
 * inactive page directory). */
void *vmm_temp_map(uint32_t phys);
void  vmm_temp_unmap(void);

/* Free all user frames, user page tables, and the page directory itself of an
 * address space. The directory must NOT be the currently loaded one. */
void vmm_destroy_address_space(uint32_t pd_phys);
