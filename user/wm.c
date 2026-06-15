/* AuroraOS compositor + window chrome — see wm.h. Portable, gfx-only. */
#include "wm.h"

#define WIN_RADIUS 10

void wm_draw_window(gfx_surface_t *screen, const window_t *win)
{
    int cw = win->content->width;
    int ch = win->content->height;
    int x = win->x, y = win->y;
    int total_h = ch + WM_TITLEBAR_H;

    uint32_t title_bg = GFX_RGB(0xec, 0xec, 0xf0);
    uint32_t white    = GFX_RGB(0xff, 0xff, 0xff);

    /* Hard drop shadow (soft/alpha shadows arrive with the design system, 9.6). */
    gfx_fill_round_rect(screen, x + 4, y + 6, cw, total_h, WIN_RADIUS, GFX_RGB(0x14, 0x14, 0x1e));

    /* Content panel (rounded), then the title bar (rounded top, square bottom). */
    gfx_fill_round_rect(screen, x, y, cw, total_h, WIN_RADIUS, white);
    gfx_fill_round_rect(screen, x, y, cw, WM_TITLEBAR_H, WIN_RADIUS, title_bg);
    gfx_fill_rect(screen, x, y + WM_TITLEBAR_H - WIN_RADIUS, cw, WIN_RADIUS, title_bg);
    gfx_fill_rect(screen, x, y + WM_TITLEBAR_H - 1, cw, 1, GFX_RGB(0xd2, 0xd2, 0xd8));

    /* Traffic-light buttons. */
    gfx_fill_circle(screen, x + 16, y + 14, 6, GFX_RGB(0xff, 0x5f, 0x57));
    gfx_fill_circle(screen, x + 34, y + 14, 6, GFX_RGB(0xfe, 0xbc, 0x2e));
    gfx_fill_circle(screen, x + 52, y + 14, 6, GFX_RGB(0x28, 0xc8, 0x40));

    /* Centered title. */
    if (win->title) {
        int tw = gfx_text_width(win->title);
        gfx_draw_text(screen, x + (cw - tw) / 2, y + 6, win->title, GFX_RGB(0x33, 0x33, 0x3a));
    }

    /* The app's content surface (packed, pitch == width*4). */
    gfx_blit(screen, x, y + WM_TITLEBAR_H, (const uint32_t *)win->content->pixels, cw, ch);
}

void wm_composite(gfx_surface_t *screen, window_t *windows[], int n)
{
    int order[WM_MAX_WINDOWS];
    if (n > WM_MAX_WINDOWS)
        n = WM_MAX_WINDOWS;
    for (int i = 0; i < n; i++)
        order[i] = i;

    /* Stable-ish sort of indices by ascending z (n is tiny). */
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n - 1 - i; j++)
            if (windows[order[j]]->z > windows[order[j + 1]]->z) {
                int t = order[j]; order[j] = order[j + 1]; order[j + 1] = t;
            }

    for (int k = 0; k < n; k++) {
        window_t *w = windows[order[k]];
        if (w->visible)
            wm_draw_window(screen, w);
    }
}
