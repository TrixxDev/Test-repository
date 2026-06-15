#include "fb.h"
#include "gfx.h"
#include "desktop.h"
#include "paging.h"
#include "kio.h"

static gfx_surface_t screen;
static int active;

int fb_init(const multiboot_info_t *mb)
{
    if (!(mb->flags & MULTIBOOT_FLAG_FB))
        return 0;                       /* loader gave us no framebuffer */
    if (mb->framebuffer_type != MULTIBOOT_FB_TYPE_RGB || mb->framebuffer_bpp != 32)
        return 0;                       /* only 32-bpp direct color for now */

    uint32_t addr  = (uint32_t)mb->framebuffer_addr;   /* low 32 bits on i686 */
    uint32_t pitch = mb->framebuffer_pitch;
    uint32_t h     = mb->framebuffer_height;
    uint32_t size  = pitch * h;

    /* Identity-map the framebuffer region so the CPU can write to it. */
    for (uint32_t off = 0; off < size; off += 0x1000)
        vmm_map_page(addr + off, addr + off, PAGE_PRESENT | PAGE_WRITE);

    screen.pixels = (uint8_t *)addr;
    screen.width  = (int)mb->framebuffer_width;
    screen.height = (int)h;
    screen.pitch  = (int)pitch;
    screen.bpp    = 32;
    active = 1;

    kprintf("[fb] framebuffer %ux%u x32 at 0x%x (pitch %u)\n",
            mb->framebuffer_width, h, addr, pitch);
    return 1;
}

void fb_draw_desktop(void)
{
    if (active)
        desktop_render(&screen);
}
