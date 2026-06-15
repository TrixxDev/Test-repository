/* AuroraOS first desktop — see desktop.h. Shapes only (no fonts/alpha yet). */
#include "desktop.h"

#define MENUBAR_H   28
#define DOCK_ICONS   5

void desktop_render(gfx_surface_t *s)
{
    int W = s->width, H = s->height;

    /* Wallpaper: a deep blue -> violet vertical gradient (macOS-ish). */
    gfx_fill_vgradient(s, 0, 0, W, H, GFX_RGB(0x18, 0x2a, 0x6e), GFX_RGB(0x52, 0x2b, 0x86));

    /* Top menu bar: a light bar with a thin separator under it. */
    gfx_fill_rect(s, 0, 0, W, MENUBAR_H, GFX_RGB(0xf4, 0xf4, 0xf8));
    gfx_fill_rect(s, 0, MENUBAR_H, W, 1, GFX_RGB(0xcf, 0xcf, 0xd6));
    /* Logo accent at the left (a rounded square stands in for the wordmark). */
    gfx_fill_round_rect(s, 12, 6, 16, 16, 4, GFX_RGB(0x33, 0x66, 0xff));
    /* A couple of status "pills" at the right. */
    gfx_fill_round_rect(s, W - 96, 9, 34, 11, 5, GFX_RGB(0x9a, 0x9a, 0xa2));
    gfx_fill_round_rect(s, W - 54, 9, 42, 11, 5, GFX_RGB(0x9a, 0x9a, 0xa2));

    /* Dock: a dark rounded panel centered near the bottom. */
    int icon = 56, pad = 16, gap = 16;
    int dock_w = DOCK_ICONS * icon + (DOCK_ICONS - 1) * gap + 2 * pad;
    int dock_h = icon + 2 * pad;
    int dock_x = (W - dock_w) / 2;
    int dock_y = H - dock_h - 20;
    gfx_fill_round_rect(s, dock_x, dock_y, dock_w, dock_h, 22, GFX_RGB(0x22, 0x22, 0x2c));

    /* App icons: rounded squares in the macOS accent palette. */
    static const uint32_t palette[DOCK_ICONS] = {
        GFX_RGB(0xff, 0x5f, 0x57),   /* red    */
        GFX_RGB(0xfe, 0xbc, 0x2e),   /* yellow */
        GFX_RGB(0x28, 0xc8, 0x40),   /* green  */
        GFX_RGB(0x33, 0x99, 0xff),   /* blue   */
        GFX_RGB(0xa8, 0x6f, 0xff),   /* purple */
    };
    for (int i = 0; i < DOCK_ICONS; i++) {
        int ix = dock_x + pad + i * (icon + gap);
        int iy = dock_y + pad;
        gfx_fill_round_rect(s, ix, iy, icon, icon, 14, palette[i]);
    }
}
