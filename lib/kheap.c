#include "kheap.h"
#include "paging.h"
#include "pmm.h"
#include <stdint.h>

/* The heap lives in its own high virtual region. Pages are allocated from the
 * PMM and mapped on demand as the heap grows. */
#define HEAP_START   0xD0000000u
#define HEAP_INITIAL (256u * 1024)          /* mapped at init */
#define HEAP_MAX     (16u * 1024 * 1024)    /* growth ceiling */
#define HEAP_MAGIC   0xCAFEB10Cu
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))

typedef struct block_header {
    uint32_t magic;
    size_t   size;          /* usable bytes after this header */
    int      free;
    struct block_header *next;
    struct block_header *prev;
} block_header_t;

static uint32_t heap_end;   /* first unmapped virtual address */
static size_t   bytes_used;
static block_header_t *head;

/* Map [heap_end, heap_end + bytes) and advance heap_end. */
static int grow_mapping(size_t bytes)
{
    uint32_t target = (uint32_t)ALIGN_UP(heap_end + bytes, PAGE_SIZE);
    if (target > HEAP_START + HEAP_MAX)
        return 0;

    while (heap_end < target) {
        uint32_t frame = pmm_alloc_frame();
        if (!frame)
            return 0;
        vmm_map_page(heap_end, frame, PAGE_PRESENT | PAGE_WRITE);
        heap_end += PAGE_SIZE;
    }
    return 1;
}

void kheap_init(void)
{
    heap_end = HEAP_START;
    bytes_used = 0;

    /* Pre-create the page tables backing the scratch page and the whole heap
     * range so they exist (and get shared by reference) when per-process
     * address spaces clone the kernel's high-memory mappings. */
    vmm_ensure_table(0xCF000000u);                  /* scratch (vmm_temp_map) */
    for (uint32_t a = HEAP_START; a < HEAP_START + HEAP_MAX; a += 0x400000)
        vmm_ensure_table(a);

    grow_mapping(HEAP_INITIAL);

    head = (block_header_t *)HEAP_START;
    head->magic = HEAP_MAGIC;
    head->size  = (heap_end - HEAP_START) - sizeof(block_header_t);
    head->free  = 1;
    head->next  = NULL;
    head->prev  = NULL;
}

/* Split `b` so it has exactly `size` usable bytes, if there is room for another
 * header plus some payload in the remainder. */
static void split_block(block_header_t *b, size_t size)
{
    if (b->size < size + sizeof(block_header_t) + 16)
        return;

    block_header_t *rest =
        (block_header_t *)((uint8_t *)b + sizeof(block_header_t) + size);
    rest->magic = HEAP_MAGIC;
    rest->size  = b->size - size - sizeof(block_header_t);
    rest->free  = 1;
    rest->prev  = b;
    rest->next  = b->next;
    if (rest->next)
        rest->next->prev = rest;

    b->size = size;
    b->next = rest;
}

/* Extend the heap by mapping more pages, growing/adding a trailing block. */
static block_header_t *expand_heap(size_t need)
{
    block_header_t *last = head;
    while (last->next)
        last = last->next;

    uint32_t old_end = heap_end;
    if (!grow_mapping(need + sizeof(block_header_t)))
        return NULL;
    size_t added = heap_end - old_end;

    if (last->free) {
        last->size += added;
        return last;
    }

    block_header_t *nb = (block_header_t *)old_end;
    nb->magic = HEAP_MAGIC;
    nb->size  = added - sizeof(block_header_t);
    nb->free  = 1;
    nb->prev  = last;
    nb->next  = NULL;
    last->next = nb;
    return nb;
}

void *kmalloc(size_t size)
{
    if (size == 0)
        return NULL;
    size = ALIGN_UP(size, 8);

    for (block_header_t *b = head; b; b = b->next) {
        if (b->free && b->size >= size) {
            split_block(b, size);
            b->free = 0;
            bytes_used += b->size;
            return (uint8_t *)b + sizeof(block_header_t);
        }
    }

    block_header_t *b = expand_heap(size);
    if (!b)
        return NULL;
    split_block(b, size);
    b->free = 0;
    bytes_used += b->size;
    return (uint8_t *)b + sizeof(block_header_t);
}

void kfree(void *ptr)
{
    if (!ptr)
        return;

    block_header_t *b = (block_header_t *)((uint8_t *)ptr - sizeof(block_header_t));
    if (b->magic != HEAP_MAGIC)
        return;     /* not a heap pointer / corruption */

    b->free = 1;
    bytes_used -= b->size;

    /* Coalesce with the following block. */
    if (b->next && b->next->free) {
        b->size += sizeof(block_header_t) + b->next->size;
        b->next = b->next->next;
        if (b->next)
            b->next->prev = b;
    }
    /* Coalesce with the preceding block. */
    if (b->prev && b->prev->free) {
        b->prev->size += sizeof(block_header_t) + b->size;
        b->prev->next = b->next;
        if (b->next)
            b->next->prev = b->prev;
    }
}

size_t kheap_used(void) { return bytes_used; }
