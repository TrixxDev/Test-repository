#include "elf.h"
#include "paging.h"
#include "pmm.h"
#include "string.h"

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

#define PT_LOAD 1
#define ET_EXEC 2
#define EM_386  3

int elf_load(const uint8_t *data, uint32_t size, uint32_t *entry_out)
{
    if (size < sizeof(elf32_ehdr_t))
        return -1;

    const elf32_ehdr_t *eh = (const elf32_ehdr_t *)data;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L'  || eh->e_ident[3] != 'F')
        return -1;
    if (eh->e_machine != EM_386 || eh->e_type != ET_EXEC)
        return -1;

    for (int i = 0; i < eh->e_phnum; i++) {
        const elf32_phdr_t *ph =
            (const elf32_phdr_t *)(data + eh->e_phoff + (uint32_t)i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD)
            continue;

        uint32_t start = ph->p_vaddr & ~0xFFFu;
        uint32_t end   = (ph->p_vaddr + ph->p_memsz + 0xFFF) & ~0xFFFu;

        for (uint32_t p = start; p < end; p += 0x1000) {
            if (vmm_get_physical(p) == 0)
                vmm_map_page(p, pmm_alloc_frame(),
                             PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        }

        /* The target pages are mapped in the current address space, so we can
         * write straight to the virtual addresses. */
        memset((void *)ph->p_vaddr, 0, ph->p_memsz);
        memcpy((void *)ph->p_vaddr, data + ph->p_offset, ph->p_filesz);
    }

    *entry_out = eh->e_entry;
    return 0;
}
