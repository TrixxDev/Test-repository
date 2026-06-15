/* A small first-fit malloc backed by sbrk(). */
#include "libc.h"

typedef struct block {
    size_t        size;
    struct block *next;
    int           free;
} block_t;

#define ALIGN(x) (((x) + 7u) & ~((size_t)7u))

static block_t *base;

static block_t *find_free(block_t **last, size_t size)
{
    block_t *b = base;
    while (b && !(b->free && b->size >= size)) {
        *last = b;
        b = b->next;
    }
    return b;
}

static block_t *extend(block_t *last, size_t size)
{
    block_t *b = (block_t *)sbrk(0);
    void *req = sbrk((int)(sizeof(block_t) + size));
    if (req == (void *)-1)
        return NULL;
    b->size = size;
    b->next = NULL;
    b->free = 0;
    if (last)
        last->next = b;
    return b;
}

void *malloc(size_t size)
{
    size = ALIGN(size);
    block_t *b;

    if (base) {
        block_t *last = base;
        b = find_free(&last, size);
        if (b)
            b->free = 0;
        else
            b = extend(last, size);
    } else {
        b = extend(NULL, size);
        base = b;
    }
    if (!b)
        return NULL;
    return (void *)(b + 1);
}

void free(void *ptr)
{
    if (!ptr)
        return;
    block_t *b = (block_t *)ptr - 1;
    b->free = 1;
}
