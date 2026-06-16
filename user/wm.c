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

    /* Traffic-light buttons; the red one (left) is the close button — mark it
     * with a small dark "x" so its action reads at a glance. */
    gfx_fill_circle(screen, x + 16, y + 14, 6, GFX_RGB(0xff, 0x5f, 0x57));
    gfx_fill_circle(screen, x + 34, y + 14, 6, GFX_RGB(0xfe, 0xbc, 0x2e));
    gfx_fill_circle(screen, x + 52, y + 14, 6, GFX_RGB(0x28, 0xc8, 0x40));
    uint32_t xmark = GFX_RGB(0x7a, 0x12, 0x10);
    for (int d = -2; d <= 2; d++) {
        gfx_fill_rect(screen, x + 16 + d, y + 14 + d, 1, 1, xmark);   /* "\" */
        gfx_fill_rect(screen, x + 16 + d, y + 14 - d, 1, 1, xmark);   /* "/" */
    }

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
    st->cursor_x = 0;
    st->cursor_y = 0;
    st->cursor_on = 0;          /* the windowserver turns this on; host renderer leaves it off */
}

int wm_create(wm_state_t *st, int x, int y, int w, int h, const char *title,
              void *pixels, int owner)
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
        st->win[i].owner = owner;
        st->win[i].title = st->titles[i];
        st->win[i].content = &st->surf[i];
        return st->win[i].id;
    }
    return -1;
}

int wm_focus_owner(wm_state_t *st)
{
    int best = -1, best_z = -1;
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].visible && st->win[i].z > best_z) {
            best_z = st->win[i].z;
            best = st->win[i].owner;
        }
    return best;
}

/* A window's full frame is its content box plus the title bar on top. */
static int frame_hit(const window_t *w, int x, int y)
{
    int cw = w->content->width;
    int total_h = w->content->height + WM_TITLEBAR_H;
    return x >= w->x && x < w->x + cw && y >= w->y && y < w->y + total_h;
}

int wm_window_at(wm_state_t *st, int x, int y)
{
    int best = -1, best_z = -1;
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].visible &&
            st->win[i].z > best_z && frame_hit(&st->win[i], x, y)) {
            best_z = st->win[i].z;
            best = st->win[i].id;
        }
    return best;
}

int wm_in_titlebar(wm_state_t *st, int id, int x, int y)
{
    int s = slot_of(st, id);
    if (s < 0)
        return 0;
    window_t *w = &st->win[s];
    return x >= w->x && x < w->x + w->content->width &&
           y >= w->y && y < w->y + WM_TITLEBAR_H;
}

/* The close button is the red traffic light at (x+16, y+14), radius 6; accept a
 * slightly larger hit radius so it is comfortable to click. */
int wm_in_close_button(wm_state_t *st, int id, int x, int y)
{
    int s = slot_of(st, id);
    if (s < 0)
        return 0;
    int cx = st->win[s].x + 16, cy = st->win[s].y + 14;
    int dx = x - cx, dy = y - cy;
    return dx * dx + dy * dy <= 9 * 9;
}

int wm_window_x(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    return s < 0 ? 0 : st->win[s].x;
}

int wm_window_y(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    return s < 0 ? 0 : st->win[s].y;
}

int wm_owner_of(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    return s < 0 ? -1 : st->win[s].owner;
}

int wm_window_of_owner(wm_state_t *st, int owner)
{
    int best = -1, best_z = -1;
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].owner == owner && st->win[i].z > best_z) {
            best_z = st->win[i].z;
            best = st->win[i].id;
        }
    return best;
}

int wm_window_bounds(wm_state_t *st, int id, int *bx, int *by, int *bw, int *bh)
{
    int s = slot_of(st, id);
    if (s < 0)
        return 0;
    /* The window spans content + title bar; wm_draw_window adds a hard drop
     * shadow offset by (+4, +6), so the on-screen footprint is that much wider
     * and taller. (Keep this in sync with WIN_RADIUS/shadow in wm_draw_window.) */
    int cw = st->win[s].content->width;
    int total_h = st->win[s].content->height + WM_TITLEBAR_H;
    *bx = st->win[s].x;
    *by = st->win[s].y;
    *bw = cw + 4;
    *bh = total_h + 6;
    return 1;
}

void wm_raise(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    if (s >= 0)
        st->win[s].z = st->next_z++;    /* highest z => focused + drawn last */
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

void wm_move_clamped(wm_state_t *st, int id, int x, int y, int screen_w, int screen_h)
{
    int s = slot_of(st, id);
    if (s < 0)
        return;
    int cw = st->win[s].content->width;
    int margin = 40;                /* min graspable strip kept on-screen */

    if (x > screen_w - margin)      x = screen_w - margin;
    if (x < margin - cw)            x = margin - cw;     /* keep some right edge */
    if (y < WM_MENUBAR_H)           y = WM_MENUBAR_H;    /* never under the menu bar */
    if (y > screen_h - margin)      y = screen_h - margin;

    st->win[s].x = x;
    st->win[s].y = y;
}

void wm_destroy(wm_state_t *st, int id)
{
    int s = slot_of(st, id);
    if (s >= 0) { st->used[s] = 0; st->count--; }
}

/* Arrow cursor, drawn last (on top of everything). '#' = dark outline,
 * '*' = white fill, anything else = transparent. */
static const char *const cursor_glyph[] = {
    "#",
    "##",
    "#*#",
    "#**#",
    "#***#",
    "#****#",
    "#*****#",
    "#******#",
    "#*******#",
    "#********#",
    "#*****#####",
    "#**#**#",
    "#*# #**#",
    "##  #**#",
    "#    #**#",
    "     #**#",
    "      ###",
};

void wm_draw_cursor(gfx_surface_t *screen, int px, int py)
{
    uint32_t outline = GFX_RGB(0x11, 0x11, 0x14);
    uint32_t fill    = GFX_RGB(0xff, 0xff, 0xff);
    int rows = (int)(sizeof(cursor_glyph) / sizeof(cursor_glyph[0]));
    for (int r = 0; r < rows; r++) {
        const char *line = cursor_glyph[r];
        for (int c = 0; line[c]; c++) {
            uint32_t color;
            if (line[c] == '#')      color = outline;
            else if (line[c] == '*') color = fill;
            else                     continue;
            gfx_fill_rect(screen, px + c, py + r, 1, 1, color);
        }
    }
}

void wm_compose(wm_state_t *st, gfx_surface_t *screen)
{
    desktop_render(screen);                   /* wallpaper + menu bar + dock */
    window_t *vis[WM_MAX_WINDOWS];
    int n = 0;
    for (int i = 0; i < WM_MAX_WINDOWS; i++)
        if (st->used[i] && st->win[i].visible)
            vis[n++] = &st->win[i];
    wm_composite(screen, vis, n);             /* windows, back-to-front; no cursor */
}

void wm_present(wm_state_t *st, gfx_surface_t *screen)
{
    wm_compose(st, screen);
    if (st->cursor_on)                        /* pointer on top of everything */
        wm_draw_cursor(screen, st->cursor_x, st->cursor_y);
}
