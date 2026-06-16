/* AuroraOS desktop background — see desktop.h. Wallpaper + menu bar + greeting.
 *
 * The Dock is no longer drawn here: as of 9.6 it is its own userspace process
 * (user/dock.c), a borderless window owned by the window server like any other
 * GUI client. This file only paints the static background behind all windows. */
#include "desktop.h"

#define MENUBAR_H   28

void desktop_render(gfx_surface_t *s)
{
    int W = s->width, H = s->height;

    /* Wallpaper: a deep blue -> violet vertical gradient (macOS-ish). */
    gfx_fill_vgradient(s, 0, 0, W, H, GFX_RGB(0x18, 0x2a, 0x6e), GFX_RGB(0x52, 0x2b, 0x86));

    /* Top menu bar: a light bar with a thin separator under it. */
    gfx_fill_rect(s, 0, 0, W, MENUBAR_H, GFX_RGB(0xf4, 0xf4, 0xf8));
    gfx_fill_rect(s, 0, MENUBAR_H, W, 1, GFX_RGB(0xcf, 0xcf, 0xd6));
    /* Logo accent + wordmark, then menu items. */
    gfx_fill_round_rect(s, 12, 6, 16, 16, 4, GFX_RGB(0x33, 0x66, 0xff));
    uint32_t ink = GFX_RGB(0x22, 0x22, 0x2a), dim = GFX_RGB(0x55, 0x55, 0x60);
    gfx_draw_text(s, 36, 6, "Aurora", ink);
    gfx_draw_text(s, 100, 6, "File",   dim);
    gfx_draw_text(s, 148, 6, "Edit",   dim);
    gfx_draw_text(s, 196, 6, "View",   dim);
    gfx_draw_text(s, 244, 6, "Window", dim);
    gfx_draw_text(s, 308, 6, "Help",   dim);
    /* A clock at the right. */
    const char *clock = "12:26";
    gfx_draw_text(s, W - gfx_text_width(clock) - 14, 6, clock, ink);

    /* A centered greeting on the wallpaper. */
    const char *hello = "Welcome to AuroraOS";
    gfx_draw_text(s, (W - gfx_text_width(hello)) / 2, H / 2 - 8, hello, GFX_RGB(0xe8, 0xe8, 0xf2));
}
