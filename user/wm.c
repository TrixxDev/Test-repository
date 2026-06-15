/* AuroraOS compositor + window-server core — see wm.h. Portable, gfx-only. */
#include "wm.h"
#include "desktop.h"

#define WIN_RADIUS 10

/* ---- compositor primitives ---- */

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

    /* The window's content surface (packed, pitch == width*4). */
    gfx_blit(screen, x, y + WM_TITLEBAR_H, (const uint32_t *)win->content->pixels, cw, ch);
}

void wm_composite(gfx_surface_t *screen, window_t *windows[], int n)
{
    int order[WM_MAX_WINDOWS];
    if (n > WM_MAX_WINDOWS)
        n = WM_MAX_WINDOWS;
    for (int i = 0; i < n; i++)
        order[i] = i;

    for (int i = 0; i < n; i++)               /* sort indices by ascending z */
        for (int j = 0; j < n - 1 - i; j++)
            if (windows[order[j]]->z > windows[order[j + 1]]->z) {
                int t = order[j]; order[j] = order[j + 1]; order[j + 1] = t;
            }

    for (int k = 0; k < n; k++)
        if (windows[order[k]]->visible)
            wm_draw_window(screen, windows[order[k]]);
}

/* ---- window-server core ---- */

static void copy_title(char *dst, const char *src)
{
    int i = 0;
    while (src && src[i] && i < 47) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static int slot_of(wm_state_t *st, int id)
{
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].id == id)
            return i;
    return -1;
}

void wm_state_init(wm_state_t *st)
{
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        st->used[i] = 0;
    st->count = 0;
    st->next_id = 1;
    st->next_z = 1;
}

int wm_create(wm_state_t *st, int x, int y, int w, int h, const char *title, void *pixels)
{
    for (int i = 0; i < WM_MAX_WINDOWS; i++) {
        if (st->used[i])
            continue;
        st->used[i] = 1;
        st->count++;
        copy_title(st->titles[i], title);
        st->surf[i].pixels = (uint8_t *)pixels;
        st->surf[i].width = w; st->surf[i].height = h;
        st->surf[i].pitch = w * 4; st->surf[i].bpp = 32;
        st->win[i].id = st->next_id++;
        st->win[i].x = x; st->win[i].y = y;
        st->win[i].z = st->next_z++;
        st->win[i].visible = 1;
        st->win[i].title = st->titles[i];
        st->win[i].content = &st->surf[i];
        return st->win[i].id;
    }
    return -1;
}

void wm_clear(wm_state_t *st, int id, uint32_t color)
{
    int s = slot_of(st, id);
    if (s >= 0) gfx_clear(&st->surf[s], color);
}

void wm_draw_rect(wm_state_t *st, int id, int x, int y, int w, int h, uint32_t color)
{
    int s = slot_of(st, id);
    if (s >= 0) gfx_fill_rect(&st->surf[s], x, y, w, h, color);
}

void wm_draw_text(wm_state_t *st, int id, int x, int y, const char *str, uint32_t color)
{
    int s = slot_of(st, id);
    if (s >= 0) gfx_draw_text(&st->surf[s], x, y, str, color);
}

void wm_move(wm_state_t *st, int id, int x, int y)
{
    int s = slot_of(st, id);
    if (s >= 0) { st->win[s].x = x; st->win[s].y = y; }
}

void wm_destroy(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    if (s >= 0) { st->used[s] = 0; st->count--; }
}

void wm_present(wm_state_t *st, gfx_surface_t *screen)
{
    desktop_render(screen);                   /* wallpaper + menu bar + dock */
    window_t *vis[WM_MAX_WINDOWS];
    int n = 0;
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].visible)
            vis[n++] = &st->win[i];
    wm_composite(screen, vis, n);
}
