/* AuroraOS desktop background — see desktop.h. Wallpaper + menu bar + greeting.
 *
 * The Dock is no longer drawn here: as of 9.6 it is its own userspace process
 * (user/dock.c), a borderless window owned by the window server like any other
 * GUI client. This file only paints the static background behind all windows. */
#include "desktop.h"

#define MENUBAR_H   28

/* Theme palettes (see desktop.h). Index 0 is the default. */
static const uint32_t wallpaper_top[4] = {
    GFX_RGB(0x18, 0x2a, 0x6e),   /* blue   */
    GFX_RGB(0x12, 0x12, 0x1a),   /* dark   */
    GFX_RGB(0x3a, 0x1a, 0x6e),   /* purple */
    GFX_RGB(0x10, 0x3a, 0x2e),   /* green  */
};
static const uint32_t wallpaper_bottom[4] = {
    GFX_RGB(0x52, 0x2b, 0x86),
    GFX_RGB(0x24, 0x24, 0x2e),
    GFX_RGB(0x7a, 0x2b, 0x86),
    GFX_RGB(0x1e, 0x6e, 0x52),
};
static const uint32_t accent_color[4] = {
    GFX_RGB(0x33, 0x66, 0xff),   /* blue   */
    GFX_RGB(0xfe, 0x8e, 0x2e),   /* orange */
    GFX_RGB(0xa8, 0x6f, 0xff),   /* purple */
    GFX_RGB(0x28, 0xc8, 0x40),   /* green  */
};

static int g_wallpaper = 0;
static int g_accent = 0;

void desktop_set_theme(int wallpaper, int accent)
{
    if (wallpaper >= 0 && wallpaper < 4) g_wallpaper = wallpaper;
    if (accent    >= 0 && accent    < 4) g_accent    = accent;
}

uint32_t desktop_accent_color(void)
{
    return accent_color[g_accent];
}

void desktop_render(gfx_surface_t *s)
{
    int W = s->width, H = s->height;

    /* Wallpaper: a vertical gradient from the selected theme. */
    gfx_fill_vgradient(s, 0, 0, W, H, wallpaper_top[g_wallpaper], wallpaper_bottom[g_wallpaper]);

    /* Top menu bar: a light bar with a thin separator under it. */
    gfx_fill_rect(s, 0, 0, W, MENUBAR_H, GFX_RGB(0xf4, 0xf4, 0xf8));
    gfx_fill_rect(s, 0, MENUBAR_H, W, 1, GFX_RGB(0xcf, 0xcf, 0xd6));
    /* Logo accent + wordmark, then menu items. */
    gfx_fill_round_rect(s, 12, 6, 16, 16, 4, accent_color[g_accent]);
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
