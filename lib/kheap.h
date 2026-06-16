/* Kernel heap: a first-fit allocator backed by on-demand paged memory. */
#pragma once
#include <stddef.h>

void  kheap_init(void);
void *kmalloc(size_t size);
void  kfree(void *ptr);

/* Bytes currently handed out (excluding block headers). */
size_t kheap_used(void);
