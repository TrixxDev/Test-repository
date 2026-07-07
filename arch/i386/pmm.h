/* Physical memory manager: a bitmap frame allocator (4 KiB frames). */
#pragma once
#include <stdint.h>
#include "multiboot.h"

#define PAGE_SIZE 4096

/* Scan the Multiboot memory map and build the frame bitmap. */
void pmm_init(const multiboot_info_t *mb);

/* Allocate / free a single physical frame. Returns 0 on out-of-memory. */
uint32_t pmm_alloc_frame(void);
void     pmm_free_frame(uint32_t phys_addr);

/* Reporting. */
uint32_t pmm_total_frames(void);
uint32_t pmm_used_frames(void);
uint32_t pmm_free_frames(void);
