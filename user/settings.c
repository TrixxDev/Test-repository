/* Settings.app (Phase 10.3): the first AuroraOS control panel.
 *
 *   Desktop pane: pick a wallpaper + accent color. Choices are written to
 *                 /disk/settings.cfg (plain key=value) and the window server is
 *                 told to re-read them (WM_RELOAD_SETTINGS) — no new IPC, just the
 *                 VFS, exactly as the shell uses files.
 *   System pane:  read-only "About This Mac"-style info from the sysinfo syscall.
 *
 * Launched from the Aurora system menu. Talks to the windowserver over the same
 * draw protocol every other app uses; clicks arrive as WM_POINTER.
 */
#include "libc.h"
#include "wm.h"

#define BASE_W       460
#define BASE_H       320
#define BASE_SIDEBAR 120
#define BASE_X0      134            /* content area left edge */

static int wm;
static int win;
static int S = 100;                 /* UI scale percent (queried from the system) */
static int W, H, SIDEBAR, X0;       /* layout, scaled by S (set in main / on rescale) */
static int pane = 0;                /* 0 = Desktop, 1 = Display, 2 = System */
static int cur_wp = 0, cur_ac = 0;  /* current wallpaper / accent index */
static int cur_scale = 0;           /* current UI-scale index (into sc_val) */

static int sx(int v) { return v * S / 100; }   /* scale a layout literal by S */

/* (Re)compute the scaled window + content geometry from the current scale. */
static void relayout(void)
{
    W = BASE_W * S / 100; H = BASE_H * S / 100;
    SIDEBAR = BASE_SIDEBAR * S / 100; X0 = BASE_X0 * S / 100;
}

static const char *wp_cfg[4]  = { "blue", "dark", "purple", "green" };
static const char *ac_cfg[4]  = { "blue", "orange", "purple", "green" };
static const char *wp_name[4] = { "Aurora Blue", "Aurora Dark", "Aurora Purple", "Aurora Green" };
static const char *ac_name[4] = { "Blue", "Orange", "Purple", "Green" };
static const uint32_t wp_sw[4] = {
    GFX_RGB(0x2a,0x3a,0x86), GFX_RGB(0x20,0x20,0x2a),
    GFX_RGB(0x5a,0x2b,0x86), GFX_RGB(0x1e,0x6e,0x52),
};
static const uint32_t ac_sw[4] = {
    GFX_RGB(0x33,0x66,0xff), GFX_RGB(0xfe,0x8e,0x2e),
    GFX_RGB(0xa8,0x6f,0xff), GFX_RGB(0x28,0xc8,0x40),
};

/* row layout for the Desktop pane (content-local y of each option group), scaled */
#define WP_Y0 sx(40)
#define AC_Y0 sx(168)
#define ROW_H sx(24)

/* Display pane: UI-scale list (top) + resolution list (below). */
#define SC_Y0  sx(36)        /* first UI-scale row   */
#define RES_Y0 sx(174)       /* first resolution row */
static const char    *sc_name[4] = { "100%", "125%", "150%", "200%" };
static const int      sc_val[4]  = { 100, 125, 150, 200 };
#define RES_N 5
static const char    *res_name[RES_N] = { "800x600", "1024x768", "1280x720", "1366x768", "1920x1080" };
static int cur_res = 1;      /* current resolution index (default 1024x768) */

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

static void utoa(unsigned v, char *dst)
{
    char tmp[12]; int n = 0;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    int p = 0; while (n > 0) dst[p++] = tmp[--n]; dst[p] = '\0';
}

/* "label: NNN unit" */
static void line_kv(int y, const char *label, unsigned v, const char *unit)
{
    char buf[64]; int p = 0;
    for (int i = 0; label[i]; i++) buf[p++] = label[i];
    char num[12]; utoa(v, num);
    for (int i = 0; num[i]; i++) buf[p++] = num[i];
    if (unit) { buf[p++] = ' '; for (int i = 0; unit[i]; i++) buf[p++] = unit[i]; }
    buf[p] = '\0';
    text(X0, y, buf, GFX_RGB(0x33, 0x33, 0x3a));
}

static void option_row(int y, uint32_t swatch, const char *name, int selected)
{
    int sw = sx(16);
    if (selected) rect(X0 - sx(6), y - sx(3), W - X0 - sx(4), ROW_H, GFX_RGB(0xdf, 0xe7, 0xff));
    rect(X0, y, sw, sw, swatch);
    rect(X0, y, sw, 1, GFX_RGB(0x88,0x88,0x90)); rect(X0, y+sw-1, sw, 1, GFX_RGB(0x88,0x88,0x90));
    rect(X0, y, 1, sw, GFX_RGB(0x88,0x88,0x90)); rect(X0+sw-1, y, 1, sw, GFX_RGB(0x88,0x88,0x90));
    text(X0 + sx(26), y, name, GFX_RGB(0x22, 0x22, 0x2a));
    if (selected) text(W - sx(26), y, "*", GFX_RGB(0x33, 0x66, 0xff));
}

/* A selectable text row (no color swatch) for the Display pane's scale list. */
static void pick_row(int y, const char *name, int selected)
{
    if (selected) rect(X0 - sx(6), y - sx(3), W - X0 - sx(4), ROW_H, GFX_RGB(0xdf, 0xe7, 0xff));
    text(X0, y, name, GFX_RGB(0x22, 0x22, 0x2a));
    if (selected) text(W - sx(26), y, "*", GFX_RGB(0x33, 0x66, 0xff));
}

static void redraw(void)
{
    /* Clear the whole content surface (its allocated size may exceed the current
     * scaled W,H if the scale was lowered after creation; the server clips to the
     * real surface), so a live rescale never leaves stale pixels behind. */
    rect(0, 0, BASE_W * WM_MAX_UI_SCALE / 100, BASE_H * WM_MAX_UI_SCALE / 100,
         GFX_RGB(0xf6, 0xf6, 0xf9));
    rect(0, 0, W, H, GFX_RGB(0xf6, 0xf6, 0xf9));
    rect(0, 0, SIDEBAR, H, GFX_RGB(0xec, 0xec, 0xf1));        /* sidebar */
    rect(SIDEBAR, 0, 1, H, GFX_RGB(0xd5, 0xd5, 0xdc));
    rect(0, sx(10) + pane * sx(28), SIDEBAR, sx(22), GFX_RGB(0xdf, 0xe7, 0xff)); /* active row */
    text(sx(16), sx(13), "Desktop", GFX_RGB(0x22, 0x22, 0x2a));
    text(sx(16), sx(41), "Display", GFX_RGB(0x22, 0x22, 0x2a));
    text(sx(16), sx(69), "System",  GFX_RGB(0x22, 0x22, 0x2a));

    if (pane == 0) {
        text(X0, sx(12), "Wallpaper", GFX_RGB(0x11, 0x11, 0x18));
        for (int i = 0; i < 4; i++)
            option_row(WP_Y0 + i * ROW_H, wp_sw[i], wp_name[i], i == cur_wp);
        text(X0, AC_Y0 - sx(28), "Accent Color", GFX_RGB(0x11, 0x11, 0x18));
        for (int i = 0; i < 4; i++)
            option_row(AC_Y0 + i * ROW_H, ac_sw[i], ac_name[i], i == cur_ac);
    } else if (pane == 1) {
        text(X0, sx(12), "UI Scale", GFX_RGB(0x11, 0x11, 0x18));
        for (int i = 0; i < 4; i++)
            pick_row(SC_Y0 + i * ROW_H, sc_name[i], i == cur_scale);
        text(X0, sx(150), "Resolution", GFX_RGB(0x11, 0x11, 0x18));
        for (int i = 0; i < RES_N; i++)
            pick_row(RES_Y0 + i * ROW_H, res_name[i], i == cur_res);
    } else {
        struct sysinfo si;
        memset(&si, 0, sizeof(si));
        sysinfo(&si);
        text(X0, sx(14), "About AuroraOS", GFX_RGB(0x11, 0x11, 0x18));
        text(X0, sx(40), "AuroraOS v1.1.2", GFX_RGB(0x33, 0x33, 0x3a));
        line_kv(sx(64),  "RAM total:  ", si.ram_kb,         "KiB");
        line_kv(sx(84),  "RAM used:   ", si.ram_used_kb,    "KiB");
        line_kv(sx(104), "Free pages: ", si.free_frames,    0);
        line_kv(sx(124), "Processes:  ", si.procs,          0);
        line_kv(sx(144), "Uptime:     ", si.uptime_ms / 1000, "s");
    }
    present();
}

static void write_cfg(void)
{
    char buf[128]; int p = 0;
    const char *k1 = "wallpaper=";
    for (int i = 0; k1[i]; i++) buf[p++] = k1[i];
    for (int i = 0; wp_cfg[cur_wp][i]; i++) buf[p++] = wp_cfg[cur_wp][i];
    buf[p++] = '\n';
    const char *k2 = "accent=";
    for (int i = 0; k2[i]; i++) buf[p++] = k2[i];
    for (int i = 0; ac_cfg[cur_ac][i]; i++) buf[p++] = ac_cfg[cur_ac][i];
    buf[p++] = '\n';
    const char *k3 = "ui_scale=";
    for (int i = 0; k3[i]; i++) buf[p++] = k3[i];
    char num[12]; utoa((unsigned)sc_val[cur_scale], num);
    for (int i = 0; num[i]; i++) buf[p++] = num[i];
    buf[p++] = '\n';
    const char *k4 = "resolution=";
    for (int i = 0; k4[i]; i++) buf[p++] = k4[i];
    for (int i = 0; res_name[cur_res][i]; i++) buf[p++] = res_name[cur_res][i];
    buf[p++] = '\n';

    int fd = open("/disk/settings.cfg", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0) { write(fd, buf, p); close(fd); }

    wm_req_t r; memset(&r, 0, sizeof(r));      /* ask the WM to re-read the settings */
    r.op = WM_RELOAD_SETTINGS;
    msgsend(wm, &r, sizeof(r));
}

/* Minimal parse of the existing config so the UI shows the current choice. */
static void read_cfg(void)
{
    int fd = open("/disk/settings.cfg", O_RDONLY);
    if (fd < 0) return;
    char buf[256];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    for (char *p = buf; *p; ) {              /* scan key=value lines */
        if (strncmp(p, "wallpaper=", 10) == 0)
            for (int i = 0; i < 4; i++)
                if (strncmp(p + 10, wp_cfg[i], strlen(wp_cfg[i])) == 0) cur_wp = i;
        if (strncmp(p, "accent=", 7) == 0)
            for (int i = 0; i < 4; i++)
                if (strncmp(p + 7, ac_cfg[i], strlen(ac_cfg[i])) == 0) cur_ac = i;
        if (strncmp(p, "ui_scale=", 9) == 0) {
            int v = 0; const char *q = p + 9;
            while (*q >= '0' && *q <= '9') { v = v * 10 + (*q - '0'); q++; }
            for (int i = 0; i < 4; i++) if (sc_val[i] == v) cur_scale = i;
        }
        if (strncmp(p, "resolution=", 11) == 0)
            for (int i = 0; i < RES_N; i++)
                if (strncmp(p + 11, res_name[i], strlen(res_name[i])) == 0) cur_res = i;
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
}

static void on_click(int x, int y)
{
    if (x < SIDEBAR) {                          /* sidebar: switch pane */
        int np = (y < sx(34)) ? 0 : (y < sx(62)) ? 1 : (y < sx(90)) ? 2 : pane;
        if (np != pane) { pane = np; redraw(); }
        return;
    }

    if (pane == 0) {
        for (int i = 0; i < 4; i++) {           /* wallpaper rows */
            int ry = WP_Y0 + i * ROW_H;
            if (y >= ry - sx(3) && y < ry - sx(3) + ROW_H) { cur_wp = i; write_cfg(); redraw(); return; }
        }
        for (int i = 0; i < 4; i++) {           /* accent rows */
            int ry = AC_Y0 + i * ROW_H;
            if (y >= ry - sx(3) && y < ry - sx(3) + ROW_H) { cur_ac = i; write_cfg(); redraw(); return; }
        }
    } else if (pane == 1) {
        for (int i = 0; i < 4; i++) {           /* UI scale rows */
            int ry = SC_Y0 + i * ROW_H;
            if (y >= ry - sx(3) && y < ry - sx(3) + ROW_H) { cur_scale = i; write_cfg(); redraw(); return; }
        }
        for (int i = 0; i < RES_N; i++) {       /* resolution rows */
            int ry = RES_Y0 + i * ROW_H;
            if (y >= ry - sx(3) && y < ry - sx(3) + ROW_H) { cur_res = i; write_cfg(); redraw(); return; }
        }
    }
    /* pane 2 (System) is read-only */
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "settings: no window server\n"); return 1; }

    read_cfg();

    S = ui_scale();                     /* size the window + layout to the UI scale */
    relayout();

    wm_req_t r; wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 300; r.y = 180; r.w = W; r.h = H;
    { const char *t = "Settings"; int i = 0; while (t[i]) { r.str[i] = t[i]; i++; } r.str[i] = 0; }
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0) { fprintf(2, "settings: create failed\n"); return 1; }
    win = rep.win;

    redraw();
    printf("[settings] ready (pid %d), window %d\n", getpid(), win);

    int prev = 0;
    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;
        if (ev.op == WM_DESTROY) { printf("[settings] closed\n"); return 0; }
        if (ev.op == WM_SCALE) {
            /* The UI scale changed: re-lay-out to the new scaled size and ask the
             * server to grow/shrink our window+surface to match, then redraw when
             * it confirms (WM_RESIZE) — so the larger layout is never clipped. */
            S = ui_scale(); relayout();
            wm_req_t rr; memset(&rr, 0, sizeof(rr));
            rr.op = WM_RESIZE_REQ; rr.w = W; rr.h = H;
            msgsend(wm, &rr, sizeof(rr));
            continue;
        }
        if (ev.op == WM_RESIZE) { W = ev.w; H = ev.h; redraw(); continue; }
        if (ev.op != WM_POINTER) continue;
        int press = (ev.w & 1) && !(prev & 1);
        prev = ev.w;
        if (press && ev.y >= 0) on_click(ev.x, ev.y);
    }
    return 0;
}
