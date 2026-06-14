/* Multiboot1 information structures (as passed by the bootloader / qemu). */
#pragma once
#include <stdint.h>

/* Bits in multiboot_info_t.flags that we care about. */
#define MULTIBOOT_FLAG_MEM   (1 << 0)   /* mem_lower / mem_upper valid */
#define MULTIBOOT_FLAG_MMAP  (1 << 6)   /* mmap_* valid */

/* Memory map entry types. */
#define MULTIBOOT_MEMORY_AVAILABLE 1

typedef struct {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
    uint32_t drives_length;
    uint32_t drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
    uint32_t apm_table;
} __attribute__((packed)) multiboot_info_t;

/* One entry in the E820-style memory map. Note `size` does NOT include itself,
 * so the next entry is at (uint8_t*)entry + entry->size + 4. */
typedef struct {
    uint32_t size;
    uint64_t addr;
    uint64_t len;
    uint32_t type;
} __attribute__((packed)) multiboot_mmap_entry_t;
