/* Linear framebuffer (Phase 9.0): set up from the Multiboot framebuffer info a
 * capable loader provides, then draw through the 2D library. If no framebuffer
 * is supplied, the kernel stays in VGA text mode and these are no-ops. */
#pragma once
#include "multiboot.h"

/* Map and record the Multiboot framebuffer. Returns 1 if one is active. */
int  fb_init(const multiboot_info_t *mb);

/* Render the first desktop onto the framebuffer (no-op if inactive). */
void fb_draw_desktop(void);
