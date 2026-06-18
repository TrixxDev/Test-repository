/* Aurora Files: the AuroraOS file manager (Phase 9.7) — the first GUI app that
 * browses the filesystem. Like the shell, it uses the VFS through ordinary
 * syscalls (readdir/open) with no special privileges; it is just another window
 * server client that happens to list directories.
 *
 *     Dock -> Finder -> (exec) Terminal / (exec) Viewer
 *
 * v1, deliberately minimal: list a directory, single-click to select a row,
 * click the selected row again ("double click") to open it — a directory is
 * entered, an .ELF is exec'd, anything else is handed to the Viewer (9.8). No
 * icons, no drag-and-drop, no context menus.
 */
#include "libc.h"
#include "wm.h"

#define DEF_W    380
#define DEF_H    420
#define MAX_ENTS 64

static int wm;
static int win;
static int S = 100;                 /* UI scale percent (queried from the system) */
static int W = DEF_W, H = DEF_H;    /* content size (updated on WM_RESIZE) */
static gfx_surface_t surf;          /* shared content surface (mapped from server) */
static int shm_id = -1;

/* Layout metrics scaled by the UI scale (base: 26px header, 20px rows, 8px font).
 * At S=100 these are the original constants. */
static int header_h(void) { return 26 * S / 100; }
static int row_h(void)    { int v = 20 * S / 100; return v < 1 ? 1 : v; }
static int char_w(void)   { return 8 * S / 100; }   /* 8x16 font advance */

static char          path[256] = "/disk";
static struct dirent ents[MAX_ENTS];
static int           nents;
static int           selected = -1;

/* ---- tiny string helpers ---- */

static int streq(const char *a, const char *b) { return strcmp(a, b) == 0; }

static int ends_with(const char *s, const char *suf)
{
    int ls = (int)strlen(s), lf = (int)strlen(suf);
    if (lf > ls) return 0;
    for (int i = 0; i < lf; i++)
        if (s[ls - lf + i] != suf[i]) return 0;
    return 1;
}

static void utoa(unsigned v, char *dst)
{
    char tmp[12]; int n = 0;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    int p = 0; while (n > 0) dst[p++] = tmp[--n]; dst[p] = '\0';
}

/* Join the current path and `name` into `out` ("/" stays "/name"). */
static void join_path(char *out, const char *base, const char *name)
{
    int p = 0;
    for (int i = 0; base[i]; i++) out[p++] = base[i];
    if (!(p == 1 && out[0] == '/')) out[p++] = '/';
    for (int i = 0; name[i]; i++) out[p++] = name[i];
    out[p] = '\0';
}

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
    int hh = header_h(), rh = row_h(), cw = char_w();
    int padx = 12 * S / 100, pady = 3 * S / 100;
    rect(0, 0, W, H, GFX_RGB(0xff, 0xff, 0xff));
    /* Header: a light strip with the current path. */
    rect(0, 0, W, hh, GFX_RGB(0xf0, 0xf0, 0xf4));
    rect(0, hh - 1, W, 1, GFX_RGB(0xcc, 0xcc, 0xd2));
    text(10 * S / 100, 6 * S / 100, path, GFX_RGB(0x33, 0x33, 0x3a));

    for (int i = 0; i < nents; i++) {
        int y = hh + i * rh;
        int sel = (i == selected);
        if (sel)
            rect(0, y, W, rh, GFX_RGB(0x34, 0x78, 0xf6));
        uint32_t fg = sel ? GFX_RGB(0xff, 0xff, 0xff)
                          : (ents[i].type == DT_DIR ? GFX_RGB(0x22, 0x55, 0xcc)
                                                    : GFX_RGB(0x22, 0x22, 0x2a));
        /* directories get a trailing slash; files get a right-aligned size. */
        if (ents[i].type == DT_DIR) {
            char nm[72]; int p = 0;
            for (int k = 0; ents[i].name[k] && p < 70; k++) nm[p++] = ents[i].name[k];
            if (!streq(ents[i].name, "..")) nm[p++] = '/';
            nm[p] = '\0';
            text(padx, y + pady, nm, fg);
        } else {
            text(padx, y + pady, ents[i].name, fg);
            char sz[12]; utoa(ents[i].size, sz);
            int sx = W - (int)strlen(sz) * cw - padx;
            text(sx, y + pady, sz, sel ? GFX_RGB(0xff, 0xff, 0xff) : GFX_RGB(0x99, 0x99, 0xa2));
        }
    }
    present();
}

static void load_dir(void)
{
    nents = 0;
    selected = -1;
    if (!streq(path, "/")) {        /* synthetic parent entry */
        strcpy(ents[0].name, "..");
        ents[0].type = DT_DIR; ents[0].size = 0;
        nents = 1;
    }
    struct dirent d;
    for (int i = 0; nents < MAX_ENTS && readdir(path, i, &d) == 1; i++)
        ents[nents++] = d;
}

static void go_parent(void)
{
    int last = -1;
    for (int i = 0; path[i]; i++) if (path[i] == '/') last = i;
    if (last <= 0) { path[0] = '/'; path[1] = '\0'; }
    else           { path[last] = '\0'; }
}

/* Launch a program detached (double-fork so it reparents to init for reaping). */
static void spawn(char **argv)
{
    int mid = fork();
    if (mid == 0) {
        if (fork() == 0) { execv(argv[0], argv); _exit(127); }
        _exit(0);
    }
    int st; wait(&st);
}

static void activate(int i)
{
    struct dirent *d = &ents[i];
    if (d->type == DT_DIR) {
        if (streq(d->name, "..")) go_parent();
        else {
            char np[256]; join_path(np, path, d->name);
            strcpy(path, np);
        }
        load_dir();
        redraw();
        return;
    }
    /* A file: an .ELF runs directly; anything else opens in the Viewer (9.8). */
    char full[256];
    join_path(full, path, d->name);
    if (ends_with(d->name, ".ELF") || ends_with(d->name, ".elf")) {
        char *argv[] = { full, "480", "180", 0 };       /* open beside the Finder */
        spawn(argv);
    } else {
        char *argv[] = { "/disk/VIEWER.ELF", full, 0 }; /* Viewer arrives in 9.8 */
        spawn(argv);
    }
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int dly = 0; dly < 200000; dly++) ;
    }
    if (wm <= 0) { fprintf(2, "files: no window server\n"); return 1; }

    S = ui_scale();                     /* size the window to the UI scale */
    W = DEF_W * S / 100;
    H = DEF_H * S / 100;

    wm_req_t r; wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 160; r.y = 110; r.w = W; r.h = H;
    r.flags = WM_F_RESIZABLE | WM_F_SHM;        /* render client-side, zero-copy */
    { const char *t = "Aurora Files"; int i = 0; while (t[i]) { r.str[i] = t[i]; i++; } r.str[i] = 0; }
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0 || rep.shm < 0) { fprintf(2, "files: create failed\n"); return 1; }
    win = rep.win;

    void *px = shm_map(rep.shm);                 /* map the shared content surface */
    if (!px) { fprintf(2, "files: shm map failed\n"); return 1; }
    shm_id = rep.shm;
    clip_init(wm, rep.clip);                      /* map the shared clipboard */
    surf.pixels = (uint8_t *)px;
    surf.width = W; surf.height = H; surf.pitch = W * 4; surf.bpp = 32;

    load_dir();
    redraw();
    printf("[files] ready (pid %d), window %d, listing %s (%d entries)\n",
           getpid(), win, path, nents);

    int prev_buttons = 0;
    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;
        if (ev.op == WM_DESTROY) { printf("[files] closed\n"); return 0; }
        if (ev.op == WM_RESIZE) {
            W = ev.w; H = ev.h;
            if (ev.flags >= 0) {                /* shared surface reallocated: re-map */
                void *p = shm_map(ev.flags);
                if (p) { surf.pixels = (uint8_t *)p; shm_id = ev.flags; }
            }
            surf.width = W; surf.height = H; surf.pitch = W * 4;
            redraw(); continue;
        }
        if (ev.op == WM_SCALE)  { S = ui_scale(); redraw(); continue; }
        if (ev.op == WM_KEY) {                  /* Ctrl+C: copy the selected name */
            if (ev.x == 3 && selected >= 0 && selected < nents)
                clip_set(ents[selected].name, (int)strlen(ents[selected].name));
            continue;
        }
        if (ev.op != WM_POINTER) continue;

        int press = (ev.w & 1) && !(prev_buttons & 1);
        prev_buttons = ev.w;
        if (!press) continue;
        if (ev.y < header_h()) continue;        /* header / chrome */

        int row = (ev.y - header_h()) / row_h();
        if (row < 0 || row >= nents) { selected = -1; redraw(); continue; }
        if (row == selected) activate(row);     /* click the selected row -> open */
        else { selected = row; redraw(); }      /* first click -> select */
    }
    return 0;
}
