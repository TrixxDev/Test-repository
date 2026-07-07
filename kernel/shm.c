/* Shared-memory surfaces — see shm.h.
 *
 * Lifetime is reference-counted: an object's physical frames are freed only once
 * it has been destroyed (by its creator, or because the creator died) *and* no
 * address space still maps it. This makes the window-server's realloc-on-resize
 * safe even though the server destroys the old surface before the client has
 * finished drawing into it — the frames survive until the client unmaps.
 *
 * Access control (grant model): shm_map succeeds for the creator, for a single
 * client the creator granted (shm_grant), or for an object the creator marked
 * public (SHM_PUBLIC, e.g. the shared clipboard). A process cannot map another
 * app's window surface by guessing its (small) id, and only the creator may
 * destroy or grant an object. */
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
    int       creator;              /* pid that created it (owner: may destroy/grant) */
    int       granted;              /* pid the creator granted map access to, or -1 */
    int       is_public;            /* 1 = any process may map (e.g. the clipboard) */
    int       destroyed;            /* 1 = creator asked to free it; awaiting refcount==0 */
    int       refcount;             /* number of address spaces currently mapping it */
    int       nframes;
    uint32_t *frames;               /* kmalloc'd array of physical frames */
};

static struct shm_obj objs[SHM_MAX];

/* SHM_MAX must fit a process's per-mapping bitmask (process_t.shm_mapped). */
_Static_assert(SHM_MAX <= 32, "SHM_MAX exceeds the per-process shm_mapped bitmask");

static uint32_t slot_vaddr(int id) { return SHM_VBASE + (uint32_t)id * SHM_SLOT; }

static void free_obj(int id)
{
    for (int j = 0; j < objs[id].nframes; j++)
        pmm_free_frame(objs[id].frames[j]);
    kfree(objs[id].frames);
    memset(&objs[id], 0, sizeof(objs[id]));
    objs[id].granted = -1;
}

int shm_create(uint32_t size, uint32_t flags)
{
    if (size == 0 || size > SHM_SLOT)       /* reject before the rounding add wraps */
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

    objs[id].used      = 1;
    objs[id].creator   = process_current()->pid;
    objs[id].granted   = -1;
    objs[id].is_public = (flags & SHM_PUBLIC) ? 1 : 0;
    objs[id].destroyed = 0;
    objs[id].refcount  = 0;
    objs[id].nframes   = (int)nfr;
    objs[id].frames    = fr;
    return id;
}

uint32_t shm_map(int id)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return 0;
    process_t *p = process_current();
    if (objs[id].creator != p->pid && objs[id].granted != p->pid && !objs[id].is_public)
        return 0;                            /* not ours to map */

    uint32_t va  = slot_vaddr(id);
    uint32_t bit = 1u << id;
    if (!(p->shm_mapped & bit)) {            /* first mapping by this process */
        for (int i = 0; i < objs[id].nframes; i++)
            vmm_map_page(va + (uint32_t)i * 4096, objs[id].frames[i],
                         PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_SHARED);
        p->shm_mapped |= bit;
        objs[id].refcount++;
    }
    return va;
}

int shm_unmap(int id)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return -1;
    process_t *p = process_current();
    uint32_t bit = 1u << id;
    if (!(p->shm_mapped & bit))
        return -1;                           /* this process did not map it */

    uint32_t va = slot_vaddr(id);
    for (int i = 0; i < objs[id].nframes; i++)
        vmm_unmap_page(va + (uint32_t)i * 4096);
    p->shm_mapped &= ~bit;
    objs[id].refcount--;
    if (objs[id].destroyed && objs[id].refcount == 0)
        free_obj(id);                        /* last mapper of a destroyed object */
    return 0;
}

int shm_grant(int id, int pid)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return -1;
    if (objs[id].creator != process_current()->pid)
        return -1;                           /* only the creator may grant */
    objs[id].granted = pid;
    return 0;
}

int shm_destroy(int id)
{
    if (id < 0 || id >= SHM_MAX || !objs[id].used)
        return -1;
    process_t *p = process_current();
    if (objs[id].creator != p->pid)
        return -1;                           /* only the creator may destroy */

    uint32_t bit = 1u << id;
    if (p->shm_mapped & bit) {               /* drop the caller's own mapping first */
        uint32_t va = slot_vaddr(id);
        for (int i = 0; i < objs[id].nframes; i++)
            vmm_unmap_page(va + (uint32_t)i * 4096);
        p->shm_mapped &= ~bit;
        objs[id].refcount--;
    }
    objs[id].destroyed = 1;
    if (objs[id].refcount == 0)
        free_obj(id);                        /* no other mapper: free now */
    return 0;                                /* else: freed when the last mapper unmaps */
}

void shm_release_proc(process_t *p)
{
    /* The process is exiting or exec'ing; its whole address space is being torn
     * down by the caller, so we only fix bookkeeping (no per-page vmm_unmap). */

    /* 1. Drop every mapping it held. */
    for (int id = 0; id < SHM_MAX; id++)
        if ((p->shm_mapped & (1u << id)) && objs[id].used && objs[id].refcount > 0)
            objs[id].refcount--;
    p->shm_mapped = 0;

    /* 2. Objects it created are now ownerless: mark them destroyed. */
    for (int id = 0; id < SHM_MAX; id++)
        if (objs[id].used && objs[id].creator == p->pid)
            objs[id].destroyed = 1;

    /* 3. Reap anything now fully released (destroyed with no remaining mappers). */
    for (int id = 0; id < SHM_MAX; id++)
        if (objs[id].used && objs[id].destroyed && objs[id].refcount == 0)
            free_obj(id);
}
