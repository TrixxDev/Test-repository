/* Dock.app: the first standalone GUI client of the AuroraOS window server
 * (Phase 9.6). It is an ordinary userspace process — not part of the compositor
 * and no longer drawn by desktop.c. It asks the window server for a *borderless*
 * window (WM_F_DOCK: pinned to the bottom-center, always on top, excluded from
 * keyboard focus), draws a rounded panel of app icons into it, and reacts to the
 * pointer events the server forwards (WM_POINTER): it highlights the hovered icon
 * and, on a click, launches the corresponding app.
 *
 *     mouse -> windowserver -> WM_POINTER -> dock -> fork/exec the app
 *
 * No animations, no alpha — the rounded panel uses the window server's 1-bit
 * color-key transparency (WM_COLOR_KEY) so the desktop shows through its corners.
 */
#include "libc.h"
#include "wm.h"

#define ICONS    5
#define BASE_ICON 56
#define BASE_PAD  16
#define BASE_GAP  16
#define BASE_DOCK_W (ICONS * BASE_ICON + (ICONS - 1) * BASE_GAP + 2 * BASE_PAD)
#define BASE_DOCK_H (BASE_ICON + 2 * BASE_PAD)

static int wm;
static int win;
static int S = 100;             /* UI scale percent (queried from the system) */

/* Scaled metrics. The dock is created once at boot and never recreated, so its
 * surface is allocated for the LARGEST scale (max_w x max_h); the panel is drawn
 * for the current scale, bottom-center-aligned within that surface (the surplus
 * is color-keyed transparent). So a live scale change just re-lays-out within the
 * fixed surface — correct at any scale, no realloc. */
static int icon_sz(void) { return BASE_ICON * S / 100; }
static int pad(void)     { return BASE_PAD  * S / 100; }
static int gap(void)     { return BASE_GAP  * S / 100; }
static int dock_w(void)  { return ICONS * icon_sz() + (ICONS - 1) * gap() + 2 * pad(); }
static int dock_h(void)  { return icon_sz() + 2 * pad(); }
static int max_w(void)   { return BASE_DOCK_W * WM_MAX_UI_SCALE / 100; }
static int max_h(void)   { return BASE_DOCK_H * WM_MAX_UI_SCALE / 100; }
static int off_x(void)   { return (max_w() - dock_w()) / 2; }  /* center in surface  */
static int off_y(void)   { return max_h() - dock_h(); }        /* bottom-align        */

/* Each slot: a letter, an accent color, and the program it launches (or NULL
 * for a not-yet-built app, which just highlights on hover). */
static const struct {
    char        label;
    uint32_t    color;
    const char *path;
} slots[ICONS] = {
    { 'T', GFX_RGB(0xff, 0x5f, 0x57), "/disk/TERM.ELF"  },  /* Terminal */
    { 'F', GFX_RGB(0xfe, 0xbc, 0x2e), "/disk/FILES.ELF" },  /* Aurora Files (Finder) */
    { 'E', GFX_RGB(0x28, 0xc8, 0x40), "/disk/WMSTRESS.ELF" },  /* diagnostics: WS stress self-test */
    { 'N', GFX_RGB(0x33, 0x99, 0xff), "/disk/FETCH.ELF" },  /* Aurora Fetch (network) */
    { 'S', GFX_RGB(0xa8, 0x6f, 0xff), 0               },  /* Settings */
};

static gfx_surface_t surf;      /* the shared content surface (mapped from the server) */

static void wsend(wm_req_t *r) { msgsend(wm, r, sizeof(*r)); }

static int icon_x(int i) { return off_x() + pad() + i * (icon_sz() + gap()); }

/* Which icon (0..ICONS-1) does the content-local point fall on, or -1. */
static int icon_at(int x, int y)
{
    int iy0 = off_y() + pad(), sz = icon_sz();
    if (y < iy0 || y >= iy0 + sz)
        return -1;
    for (int i = 0; i < ICONS; i++)
        if (x >= icon_x(i) && x < icon_x(i) + sz)
            return i;
    return -1;
}

static void redraw(int hover)
{
    int sz = icon_sz(), iy = off_y() + pad();
    int fw = 8 * S / 100, fh = 16 * S / 100;
    /* Client-side rendering: draw straight into the shared surface (no per-shape
     * WM_DRAW_* IPC) and tell the server to composite with one WM_PRESENT. Clear
     * the whole (max-size) surface to the color key, then draw the rounded panel
     * for the current scale, bottom-center within it; the corners + surplus stay
     * keyed so the wallpaper shows through (no alpha needed). */
    gfx_fill_rect(&surf, 0, 0, max_w(), max_h(), WM_COLOR_KEY);
    gfx_fill_round_rect(&surf, off_x(), off_y(), dock_w(), dock_h(), 22 * S / 100,
                        GFX_RGB(0x22, 0x22, 0x2c));

    for (int i = 0; i < ICONS; i++) {
        int ix = icon_x(i);
        if (i == hover)                 /* hover: a light tile behind the icon */
            gfx_fill_round_rect(&surf, ix - 4 * S / 100, iy - 4 * S / 100,
                                sz + 8 * S / 100, sz + 8 * S / 100, 16 * S / 100,
                                GFX_RGB(0x3c, 0x3c, 0x48));
        gfx_fill_round_rect(&surf, ix, iy, sz, sz, 14 * S / 100, slots[i].color);
        char ch[2] = { slots[i].label, 0 };
        gfx_draw_text_s(&surf, ix + (sz - fw) / 2, iy + (sz - fh) / 2, ch,
                        GFX_RGB(0xff, 0xff, 0xff), S);
    }

    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT;
    wsend(&r);
}

/* Append a base-10 int to dst (returns chars written). */
static int itoa(int v, char *dst)
{
    char tmp[12];
    int n = 0, neg = v < 0;
    unsigned u = neg ? (unsigned)(-v) : (unsigned)v;
    do { tmp[n++] = (char)('0' + u % 10); u /= 10; } while (u);
    int p = 0;
    if (neg) dst[p++] = '-';
    while (n > 0) dst[p++] = tmp[--n];
    dst[p] = '\0';
    return p;
}

/* Launch slot `i`'s program (double-fork so it reparents to init, which reaps
 * it; the Dock keeps no zombie children). Cascade windows so repeats stagger. */
static int launched;
static void launch(int i)
{
    if (!slots[i].path)
        return;
    int n = launched++;
    char xs[12], ys[12];
    itoa(300 + (n % 6) * 28, xs);   /* cascade, offset from init's Terminals */
    itoa(250 + (n % 6) * 28, ys);
    /* argv = {path, x, y}; each app sets its own title (the Finder ignores the
     * position and opens at a fixed spot). */
    char *argv[] = { (char *)slots[i].path, xs, ys, 0 };

    int mid = fork();
    if (mid == 0) {
        if (fork() == 0) {              /* grandchild: become the app */
            execv(argv[0], argv);
            _exit(127);
        }
        _exit(0);                       /* middle exits -> grandchild -> init */
    }
    int st;
    wait(&st);                          /* reap the middle child */
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0)
            for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "dock: no window server\n"); return 1; }

    S = ui_scale();             /* lay the dock out at the current UI scale */

    wm_req_t r;
    wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 0; r.y = 0; r.w = max_w(); r.h = max_h();
    r.flags = WM_F_DOCK | WM_F_SHM;     /* render client-side into a shared surface */
    { const char *t = "Dock"; int i = 0; while (t[i]) { r.str[i] = t[i]; i++; } r.str[i] = 0; }
    wsend(&r);
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0 || rep.shm < 0) {
        fprintf(2, "dock: create failed\n"); return 1;
    }
    win = rep.win;

    /* Map the shared content surface the server allocated for us and draw into it. */
    void *px = shm_map(rep.shm);
    if (!px) { fprintf(2, "dock: shm map failed\n"); return 1; }
    surf.pixels = (uint8_t *)px;
    surf.width  = max_w();
    surf.height = max_h();
    surf.pitch  = max_w() * 4;
    surf.bpp    = 32;

    int hover = -1, prev_buttons = 0;
    redraw(hover);
    printf("[dock] ready (pid %d), window %d\n", getpid(), win);

    /* Event loop: the server forwards pointer events while the cursor is over
     * the Dock. Highlight the hovered icon; launch on a left-click. */
    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev))
            continue;
        if (ev.op == WM_SCALE) { S = ui_scale(); redraw(hover); continue; }
        if (ev.op != WM_POINTER)
            continue;

        int idx     = icon_at(ev.x, ev.y);
        int buttons = ev.w;
        int press   = (buttons & 1) && !(prev_buttons & 1);

        if (idx != hover) {
            hover = idx;
            redraw(hover);
        }
        if (press && idx >= 0)
            launch(idx);
        prev_buttons = buttons;
    }
    return 0;
}
