/* Minimal ELF32 loader (executables for i386). */
#pragma once
#include <stdint.h>

/* Load all PT_LOAD segments of the ELF image in `data` into the *current*
 * address space (USER pages) and report the entry point. Returns 0 on success. */
int elf_load(const uint8_t *data, uint32_t size, uint32_t *entry_out);
