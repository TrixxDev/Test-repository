/* Process model v2: a process is an address space plus a thread loaded from
 * an ELF executable. */
#pragma once
#include <stdint.h>

/* Create a new address space, load the ELF image into it, and start it as a
 * ring-3 thread. Returns the thread id, or -1 on failure. */
int process_spawn(const uint8_t *elf, uint32_t size);
