/* Shared-memory surfaces — see shm.h. */
#include "shm.h"
#include "pmm.h"
#include "paging.h"
#include "kheap.h"
#include "string.h"
#include "process.h"

#define SHM_MAX     24              /* one per window + a spare for maximize realloc */
#define SHM_VBASE   0xA0000000u     /* between the framebuffer map and the stack */
#define SHM_SLOT    0x00A00000u     /* 10 MiB per object (fits 1920x1080x4)      */
#define SHM_MAX_FR  (SHM_SLOT / 4096)

struct shm_obj {
    int       used;
    int       creator;              /* pid that created it (for exit cleanup) */
    int       nframes;
    uint32_t *frames;               /* kmalloc'd array of physical frames */
};

static struct shm_obj objs[SHM_MAX];

static uint32_t slot_vaddr(int id) { return SHM_VBASE + (uint32_t)id * SHM_SLOT; }

static void free_obj(int id)
{
    for (int j = 0; j < objs[id].nframes; j++)
        pmm_free_frame(objs[id].frames[j]);
    kfree(objs[id].frames);
    objs[id].used = 0;
    objs[id].frames = 0;
    objs[id].nframes = 0;
    objs[id].creator = 0;
}

int shm_create(uint32_t size)
{
    if (size == 0)
        return -1;
    uint32_t nfr = (size + 4095) / 4096;
    if (nfr > SHM_MAX_FR)
        return -1;

    int id = -1;
    for (int i = 0; i < SHM_MAX; i++)
        if (!objs[i].used) { id = i; break; }
    if (id < 0)
        return -1;

    uint32_t *fr = (uint32_t *)kmalloc(nfr * sizeof(uint32_t));
    if (!fr)
        return -1;

    for (uint32_t i = 0; i < nfr; i++) {
        uint32_t f = pmm_alloc_frame();
        if (!f) {                               /* OOM: roll back */
            for (uint32_t j = 0; j < i; j++)
                pmm_free_frame(fr[j]);
            kfree(fr);
            return -1;
        }
        void *p = vmm_temp_map(f);               /* zero the new frame */
        memset(p, 0, 4096);
        vmm_temp_unmap();
        fr[i] = f;
    }

    objs[id].used = 1;
    objs[id].creator = process_current()->pid;
    objs[id].nframes = (int)nfr;
    objs[id].frames = fr;
    return id;
}

uint32_t shm_map(int id)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return 0;
    uint32_t va = slot_vaddr(id);
    for (int i = 0; i < objs[id].nframes; i++)
        vmm_map_page(va + (uint32_t)i * 4096, objs[id].frames[i],
                     PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_SHARED);
    return va;
}

int shm_destroy(int id)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return -1;
    /* Unmap from the caller's space; other mappers' PTEs are PAGE_SHARED and are
     * dropped (without freeing the frame) when their address spaces are torn down. */
    uint32_t va = slot_vaddr(id);
    for (int i = 0; i < objs[id].nframes; i++)
        vmm_unmap_page(va + (uint32_t)i * 4096);
    free_obj(id);
    return 0;
}

void shm_release_pid(int pid)
{
    /* The dying process's own mapping is being torn down by the caller; here we
     * only release objects it *created* (so a dead owner never leaks frames). */
    for (int i = 0; i < SHM_MAX; i++)
        if (objs[i].used && objs[i].creator == pid)
            free_obj(i);
}
