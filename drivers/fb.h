/* Linear framebuffer (Phase 9.0): set up from the Multiboot framebuffer info a
 * capable loader provides, then draw through the 2D library. If no framebuffer
 * is supplied, the kernel stays in VGA text mode and these are no-ops. */
#pragma once
#include "multiboot.h"

/* Map and record the Multiboot framebuffer. Returns 1 if one is active. */
int  fb_init(const multiboot_info_t *mb);

/* True if a graphics framebuffer is active (lets init pick GUI vs text mode). */
int  fb_is_active(void);

/* Render the first desktop onto the framebuffer (no-op if inactive). */
void fb_draw_desktop(void);

/* Map the active framebuffer into the current (user) address space for the
 * windowserver. Returns the user virtual base (and w/h/pitch), or 0 if no
 * framebuffer is active. */
uint32_t fb_user_map(uint32_t *w, uint32_t *h, uint32_t *pitch);

/* Change the display resolution at runtime (Bochs-VBE path only). Returns 1 on
 * success (then re-map via fb_user_map for the new geometry), 0 if unsupported. */
int fb_set_mode(uint32_t w, uint32_t h);
