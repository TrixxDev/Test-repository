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

#define ICONS 5
#define ICON  56
#define PAD   16
#define GAP   16
#define DOCK_W (ICONS * ICON + (ICONS - 1) * GAP + 2 * PAD)
#define DOCK_H (ICON + 2 * PAD)

static int wm;
static int win;

/* Each slot: a letter, an accent color, and the program it launches (or NULL
 * for a not-yet-built app, which just highlights on hover). */
static const struct {
    char        label;
    uint32_t    color;
    const char *path;
} slots[ICONS] = {
    { 'T', GFX_RGB(0xff, 0x5f, 0x57), "/disk/TERM.ELF"  },  /* Terminal */
    { 'F', GFX_RGB(0xfe, 0xbc, 0x2e), "/disk/FILES.ELF" },  /* Aurora Files (Finder) */
    { 'E', GFX_RGB(0x28, 0xc8, 0x40), 0                },  /* Editor   */
    { 'N', GFX_RGB(0x33, 0x99, 0xff), 0               },  /* Net      */
    { 'S', GFX_RGB(0xa8, 0x6f, 0xff), 0               },  /* Settings */
};

static void wsend(wm_req_t *r) { msgsend(wm, r, sizeof(*r)); }

static void rrect(int x, int y, int w, int h, int radius, uint32_t color)
{
    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_ROUND_RECT; r.win = win;
    r.x = x; r.y = y; r.w = w; r.h = h; r.flags = radius; r.color = color;
    wsend(&r);
}

static void rect(int x, int y, int w, int h, uint32_t color)
{
    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_RECT; r.win = win;
    r.x = x; r.y = y; r.w = w; r.h = h; r.color = color;
    wsend(&r);
}

static void text(int x, int y, const char *s, uint32_t color)
{
    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_TEXT; r.win = win; r.x = x; r.y = y; r.color = color;
    int i = 0; while (s[i] && i < 47) { r.str[i] = s[i]; i++; } r.str[i] = '\0';
    wsend(&r);
}

static int icon_x(int i) { return PAD + i * (ICON + GAP); }

/* Which icon (0..ICONS-1) does the content-local point fall on, or -1. */
static int icon_at(int x, int y)
{
    if (y < PAD || y >= PAD + ICON)
        return -1;
    for (int i = 0; i < ICONS; i++)
        if (x >= icon_x(i) && x < icon_x(i) + ICON)
            return i;
    return -1;
}

static void redraw(int hover)
{
    /* Transparent backdrop, then the rounded panel; the panel's corners stay
     * keyed so the wallpaper shows through (no alpha needed). */
    rect(0, 0, DOCK_W, DOCK_H, WM_COLOR_KEY);
    rrect(0, 0, DOCK_W, DOCK_H, 22, GFX_RGB(0x22, 0x22, 0x2c));

    for (int i = 0; i < ICONS; i++) {
        int ix = icon_x(i), iy = PAD;
        if (i == hover)                 /* hover: a light tile behind the icon */
            rrect(ix - 4, iy - 4, ICON + 8, ICON + 8, 16, GFX_RGB(0x3c, 0x3c, 0x48));
        rrect(ix, iy, ICON, ICON, 14, slots[i].color);
        char ch[2] = { slots[i].label, 0 };
        text(ix + (ICON - 8) / 2, iy + (ICON - 16) / 2, ch, GFX_RGB(0xff, 0xff, 0xff));
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

    wm_req_t r;
    wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 0; r.y = 0; r.w = DOCK_W; r.h = DOCK_H;
    r.flags = WM_F_DOCK;
    { const char *t = "Dock"; int i = 0; while (t[i]) { r.str[i] = t[i]; i++; } r.str[i] = 0; }
    wsend(&r);
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0) { fprintf(2, "dock: create failed\n"); return 1; }
    win = rep.win;

    int hover = -1, prev_buttons = 0;
    redraw(hover);
    printf("[dock] ready (pid %d), window %d\n", getpid(), win);

    /* Event loop: the server forwards pointer events while the cursor is over
     * the Dock. Highlight the hovered icon; launch on a left-click. */
    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev) || ev.op != WM_POINTER)
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
