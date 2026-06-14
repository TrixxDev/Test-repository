#include "pmm.h"
#include "kio.h"
#include "string.h"

/* Supports up to 1M frames = 4 GiB of physical RAM. The bitmap lives in .bss
 * (inside the kernel image), so it is automatically protected once we mark the
 * kernel's own frames as used. */
#define MAX_FRAMES (1u << 20)
#define BITMAP_WORDS (MAX_FRAMES / 32)

/* End of the kernel image, provided by the linker script. */
extern char kernel_end[];

static uint32_t frame_bitmap[BITMAP_WORDS];
static uint32_t total_frames;
static uint32_t used_frames;

static inline void bm_set(uint32_t frame)   { frame_bitmap[frame / 32] |=  (1u << (frame % 32)); }
static inline void bm_clear(uint32_t frame) { frame_bitmap[frame / 32] &= ~(1u << (frame % 32)); }
static inline int  bm_test(uint32_t frame)  { return frame_bitmap[frame / 32] & (1u << (frame % 32)); }

void pmm_init(const multiboot_info_t *mb)
{
    /* Start with everything marked used; we free what the map says is free. */
    memset(frame_bitmap, 0xFF, sizeof(frame_bitmap));
    total_frames = 0;

    if (mb->flags & MULTIBOOT_FLAG_MMAP) {
        uint32_t ptr = mb->mmap_addr;
        uint32_t end = mb->mmap_addr + mb->mmap_length;

        while (ptr < end) {
            const multiboot_mmap_entry_t *e = (const multiboot_mmap_entry_t *)ptr;

            if (e->type == MULTIBOOT_MEMORY_AVAILABLE) {
                uint64_t region_start = e->addr;
                uint64_t region_end   = e->addr + e->len;

                /* Clamp to the 32-bit / bitmap-supported range. */
                if (region_end > (uint64_t)MAX_FRAMES * PAGE_SIZE)
                    region_end = (uint64_t)MAX_FRAMES * PAGE_SIZE;

                uint32_t first = (uint32_t)(region_start / PAGE_SIZE);
                uint32_t last  = (uint32_t)(region_end / PAGE_SIZE);

                for (uint32_t f = first; f < last; f++) {
                    bm_clear(f);
                    if (f + 1 > total_frames)
                        total_frames = f + 1;
                }
            }
            ptr += e->size + 4;
        }
    } else {
        /* Fall back to mem_upper (KiB above 1 MiB) if no map was provided. */
        uint32_t mem_kb = mb->mem_upper;
        total_frames = (1024 + mem_kb) * 1024 / PAGE_SIZE;
        for (uint32_t f = 256 /* 1 MiB */; f < total_frames; f++)
            bm_clear(f);
    }

    /* Reserve everything below the end of the kernel image (covers low memory,
     * the kernel, and this bitmap). */
    uint32_t kernel_last = ((uint32_t)kernel_end + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint32_t f = 0; f < kernel_last; f++)
        bm_set(f);

    /* Count used frames for reporting. */
    used_frames = 0;
    for (uint32_t f = 0; f < total_frames; f++)
        if (bm_test(f))
            used_frames++;
}

uint32_t pmm_alloc_frame(void)
{
    for (uint32_t f = 0; f < total_frames; f++) {
        if (!bm_test(f)) {
            bm_set(f);
            used_frames++;
            return f * PAGE_SIZE;
        }
    }
    return 0;   /* out of memory */
}

void pmm_free_frame(uint32_t phys_addr)
{
    uint32_t f = phys_addr / PAGE_SIZE;
    if (bm_test(f)) {
        bm_clear(f);
        used_frames--;
    }
}

uint32_t pmm_total_frames(void) { return total_frames; }
uint32_t pmm_used_frames(void)  { return used_frames; }
uint32_t pmm_free_frames(void)  { return total_frames - used_frames; }
