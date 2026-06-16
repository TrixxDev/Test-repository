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
#define W      500
#define H      360
#define ROW_H  18
#define PAD_X  12
#define PAD_Y  8

static int wm;
static int win;

static char  fbuf[VIEWER_MAX_FILE + 1];
static int   flen;
static int   line_off[MAX_LINES];   /* byte offset of each line's start in fbuf */
static int   nlines;
static int   top;                   /* index of the first visible line          */

static const char *fpath = "/disk/POEM.TXT";

static int visible_rows(void) { return (H - 2 * PAD_Y) / ROW_H; }

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* ---- window-server drawing (same IPC the Terminal/Finder use) ---- */

static void rect(int x, int y, int w, int h, uint32_t color)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_RECT; r.win = win; r.x = x; r.y = y; r.w = w; r.h = h; r.color = color;
    msgsend(wm, &r, sizeof(r));
}

static void text(int x, int y, const char *s, uint32_t color)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_TEXT; r.win = win; r.x = x; r.y = y; r.color = color;
    int i = 0; while (s[i] && i < 47) { r.str[i] = s[i]; i++; } r.str[i] = '\0';
    msgsend(wm, &r, sizeof(r));
}

static void present(void)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT; msgsend(wm, &r, sizeof(r));
}

static void redraw(void)
{
    rect(0, 0, W, H, GFX_RGB(0xff, 0xff, 0xff));            /* paper */
    int rows = visible_rows();
    for (int r = 0; r < rows; r++) {
        int li = top + r;
        if (li >= nlines) break;
        text(PAD_X, PAD_Y + r * ROW_H, &fbuf[line_off[li]], GFX_RGB(0x1a, 0x1a, 0x22));
    }
    /* A slim scroll indicator on the right when the file overflows the window. */
    if (nlines > rows) {
        int track = H - 2 * PAD_Y;
        int knob  = track * rows / nlines;
        if (knob < 12) knob = 12;
        int maxtop = nlines - rows;
        int ky = PAD_Y + (track - knob) * (maxtop ? top : 0) / (maxtop ? maxtop : 1);
        rect(W - 6, PAD_Y, 3, track, GFX_RGB(0xe2, 0xe2, 0xe8));
        rect(W - 6, ky, 3, knob, GFX_RGB(0xb0, 0xb0, 0xbc));
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
    for (int i = 0; title[i] && i < 47; i++) r.str[i] = title[i];
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0) { fprintf(2, "viewer: create failed\n"); return 1; }
    win = rep.win;

    redraw();
    printf("[viewer] ready (pid %d), window %d, %s (%d lines)\n",
           getpid(), win, fpath, nlines);

    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;
        if (ev.op == WM_DESTROY) { printf("[viewer] closed\n"); return 0; }
        if (ev.op != WM_KEY) continue;

        int rows = visible_rows();
        int maxtop = nlines > rows ? nlines - rows : 0;
        int c = ev.x, old = top;
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
