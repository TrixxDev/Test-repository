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
    static const char *label = "TFENS";   /* Terminal, Files, Editor, Net, Settings */
    for (int i = 0; i < DOCK_ICONS; i++) {
        int ix = dock_x + pad + i * (icon + gap);
        int iy = dock_y + pad;
        gfx_fill_round_rect(s, ix, iy, icon, icon, 14, palette[i]);
        char ch[2] = { label[i], 0 };
        gfx_draw_text(s, ix + (icon - 8) / 2, iy + (icon - 16) / 2, ch, GFX_RGB(0xff, 0xff, 0xff));
    }

    /* A centered greeting on the wallpaper. */
    const char *hello = "Welcome to AuroraOS";
    gfx_draw_text(s, (W - gfx_text_width(hello)) / 2, H / 2 - 8, hello, GFX_RGB(0xe8, 0xe8, 0xf2));
}
