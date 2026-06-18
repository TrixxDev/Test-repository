/* Aurora Viewer: a minimal text file viewer (Phase 9.8) — the app that closes
 * the user-facing chain Dock -> Finder -> file -> Viewer. It is the first GUI app
 * to render user *data* (not just window chrome): open/read/close a text file and
 * draw it with the existing 8x16 bitmap font, scrollable with the arrow keys /
 * PgUp/PgDn (or j/k/space).
 *
 * Text only: no PNG/JPEG, no rich text, no UTF-8 handling. Files are capped at
 * VIEWER_MAX_FILE so a huge file can never exhaust memory.
 */
#include "libc.h"
#include "wm.h"
#include "keys.h"

#define VIEWER_MAX_FILE 65536
#define MAX_LINES       4096
#define DEF_W  500
#define DEF_H  360

static int wm;
static int win;
static int S = 100;                 /* UI scale percent (queried from the system) */
static int W = DEF_W, H = DEF_H;    /* content size (updated on WM_RESIZE) */
static gfx_surface_t surf;          /* shared content surface (mapped from server) */
static int shm_id = -1;

/* Layout metrics scaled by the UI scale (base: 18px rows, 12/8px padding). */
static int row_h(void) { int v = 18 * S / 100; return v < 1 ? 1 : v; }
static int pad_x(void) { return 12 * S / 100; }
static int pad_y(void) { return 8 * S / 100; }

static char  fbuf[VIEWER_MAX_FILE + 1];
static int   flen;
static int   line_off[MAX_LINES];   /* byte offset of each line's start in fbuf */
static int   nlines;
static int   top;                   /* index of the first visible line          */
static int   sel_line = -1;         /* selected line (Ctrl+C copies it), or -1   */

static const char *fpath = "/disk/POEM.TXT";

static int visible_rows(void) { return (H - 2 * pad_y()) / row_h(); }

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* ---- client-side drawing into the shared content surface ---- */

static void rect(int x, int y, int w, int h, uint32_t color)
{
    gfx_fill_rect(&surf, x, y, w, h, color);
}

static void text(int x, int y, const char *s, uint32_t color)
{
    gfx_draw_text_s(&surf, x, y, s, color, S);
}

static void present(void)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT; msgsend(wm, &r, sizeof(r));
}

static void redraw(void)
{
    int px = pad_x(), py = pad_y(), rh = row_h();
    rect(0, 0, W, H, GFX_RGB(0xff, 0xff, 0xff));            /* paper */
    int rows = visible_rows();
    for (int r = 0; r < rows; r++) {
        int li = top + r;
        if (li >= nlines) break;
        if (li == sel_line)                                /* selected line highlight */
            rect(0, py + r * rh - 1, W, rh, GFX_RGB(0xd6, 0xe6, 0xff));
        uint32_t fg = (li == sel_line) ? GFX_RGB(0x10, 0x2a, 0x6e) : GFX_RGB(0x1a, 0x1a, 0x22);
        text(px, py + r * rh, &fbuf[line_off[li]], fg);
    }
    /* A slim scroll indicator on the right when the file overflows the window. */
    if (nlines > rows) {
        int sw = 6 * S / 100, track = H - 2 * py;
        int knob  = track * rows / nlines;
        int kmin = 12 * S / 100;
        if (knob < kmin) knob = kmin;
        int maxtop = nlines - rows;
        int ky = py + (track - knob) * (maxtop ? top : 0) / (maxtop ? maxtop : 1);
        rect(W - sw, py, sw / 2, track, GFX_RGB(0xe2, 0xe2, 0xe8));
        rect(W - sw, ky, sw / 2, knob, GFX_RGB(0xb0, 0xb0, 0xbc));
    }
    present();
}

static void load_file(void)
{
    flen = 0; nlines = 0; top = 0;
    int fd = open(fpath, O_RDONLY);
    if (fd < 0) {
        const char *msg = "(cannot open file)";
        int i = 0; for (; msg[i]; i++) fbuf[i] = msg[i];
        fbuf[i] = '\0'; flen = i;
        line_off[nlines++] = 0;
        return;
    }
    int n;
    while (flen < VIEWER_MAX_FILE &&
           (n = read(fd, fbuf + flen, VIEWER_MAX_FILE - flen)) > 0)
        flen += n;
    close(fd);
    fbuf[flen] = '\0';

    /* Split into NUL-terminated lines in place (handle LF and CRLF). */
    line_off[nlines++] = 0;
    for (int i = 0; i < flen; i++) {
        if (fbuf[i] == '\r') fbuf[i] = '\0';
        else if (fbuf[i] == '\n') {
            fbuf[i] = '\0';
            if (nlines < MAX_LINES) line_off[nlines++] = i + 1;
        }
    }
}

static void basename_of(const char *p, char *out)
{
    int last = -1;
    for (int i = 0; p[i]; i++) if (p[i] == '/') last = i;
    int j = 0; for (int i = last + 1; p[i] && j < 40; i++) out[j++] = p[i];
    out[j] = '\0';
}

int main(int argc, char **argv)
{
    if (argc > 1) fpath = argv[1];

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int dly = 0; dly < 200000; dly++) ;
    }
    if (wm <= 0) { fprintf(2, "viewer: no window server\n"); return 1; }

    S = ui_scale();                     /* size the window to the UI scale */
    W = DEF_W * S / 100;
    H = DEF_H * S / 100;

    load_file();

    char base[48]; basename_of(fpath, base);
    char title[64]; int p = 0;
    const char *pre = "Viewer - ";
    for (int i = 0; pre[i]; i++) title[p++] = pre[i];
    for (int i = 0; base[i] && p < 47; i++) title[p++] = base[i];
    title[p] = '\0';

    wm_req_t r; wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 430; r.y = 130; r.w = W; r.h = H;
    r.flags = WM_F_RESIZABLE | WM_F_SHM;        /* render client-side, zero-copy */
    for (int i = 0; title[i] && i < 47; i++) r.str[i] = title[i];
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0 || rep.shm < 0) { fprintf(2, "viewer: create failed\n"); return 1; }
    win = rep.win;

    void *px = shm_map(rep.shm);                 /* map the shared content surface */
    if (!px) { fprintf(2, "viewer: shm map failed\n"); return 1; }
    shm_id = rep.shm;
    clip_init(wm, rep.clip);                      /* map the shared clipboard */
    surf.pixels = (uint8_t *)px;
    surf.width = W; surf.height = H; surf.pitch = W * 4; surf.bpp = 32;

    redraw();
    printf("[viewer] ready (pid %d), window %d, %s (%d lines)\n",
           getpid(), win, fpath, nlines);

    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;
        if (ev.op == WM_DESTROY) { printf("[viewer] closed\n"); return 0; }
        if (ev.op == WM_RESIZE) {            /* maximize/restore: refit the text */
            if (ev.flags >= 0) {            /* shared surface reallocated: re-map */
                void *p = shm_map(ev.flags);
                if (!p) continue;           /* map failed: keep old surface, no desync */
                if (shm_id >= 0 && shm_id != ev.flags)
                    shm_unmap(shm_id);      /* drop our ref to the previous surface */
                shm_id = ev.flags;
                surf.pixels = (uint8_t *)p;
            }
            W = ev.w; H = ev.h;
            surf.width = W; surf.height = H; surf.pitch = W * 4;
            int rows = visible_rows();
            int maxtop = nlines > rows ? nlines - rows : 0;
            top = clampi(top, 0, maxtop);
            redraw();
            continue;
        }
        if (ev.op == WM_SCALE) {             /* UI scale changed: re-flow the text */
            S = ui_scale();
            int rows = visible_rows();
            int maxtop = nlines > rows ? nlines - rows : 0;
            top = clampi(top, 0, maxtop);
            redraw();
            continue;
        }
        if (ev.op == WM_POINTER) {          /* click a line to select it */
            static int prev_btn;
            int press = (ev.w & 1) && !(prev_btn & 1);
            prev_btn = ev.w;
            if (press && ev.y >= pad_y()) {
                int li = top + (ev.y - pad_y()) / row_h();
                sel_line = (li >= 0 && li < nlines) ? li : -1;
                redraw();
            }
            continue;
        }
        if (ev.op != WM_KEY) continue;

        int rows = visible_rows();
        int maxtop = nlines > rows ? nlines - rows : 0;
        int c = ev.x, old = top;
        if (c == 3) {                       /* Ctrl+C: copy the selected (or top) line */
            int li = (sel_line >= 0 && sel_line < nlines) ? sel_line : top;
            const char *ln = &fbuf[line_off[li]];
            clip_set(ln, (int)strlen(ln));  /* full line — no longer 47-char capped */
            continue;
        }
        switch (c) {
        case KEY_DOWN: case 'j': case '\n': top++;            break;
        case KEY_UP:   case 'k':            top--;            break;
        case KEY_PGDN: case ' ':            top += rows - 1;  break;
        case KEY_PGUP: case 'b':            top -= rows - 1;  break;
        case KEY_HOME: case 'g':            top = 0;          break;
        case KEY_END:  case 'G':            top = maxtop;     break;
        default: continue;
        }
        top = clampi(top, 0, maxtop);
        if (top != old) redraw();
    }
    return 0;
}
