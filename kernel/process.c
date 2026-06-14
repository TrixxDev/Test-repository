#include "process.h"
#include "paging.h"
#include "pmm.h"
#include "elf.h"
#include "scheduler.h"

#define USTACK_TOP   0xC0000000u
#define USTACK_PAGES 4

int process_spawn(const uint8_t *elf, uint32_t size)
{
    uint32_t saved = vmm_current_directory();
    uint32_t pd    = vmm_create_address_space();

    /* Switch into the new space so elf_load / stack mapping operate on it. */
    vmm_switch_address_space(pd);

    uint32_t entry;
    if (elf_load(elf, size, &entry) != 0) {
        vmm_switch_address_space(saved);
        return -1;
    }

    for (int i = 1; i <= USTACK_PAGES; i++)
        vmm_map_page(USTACK_TOP - (uint32_t)i * 0x1000, pmm_alloc_frame(),
                     PAGE_PRESENT | PAGE_WRITE | PAGE_USER);

    vmm_switch_address_space(saved);

    return thread_create_user(pd, entry, USTACK_TOP);
}
