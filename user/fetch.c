/* Aurora Fetch: the first network GUI application.
 *
 * A tiny browser-of-one-page: type a hostname, click Fetch (or press Enter), and
 * the whole network stack runs end to end -- DNS -> TCP connect -> HTTP GET ->
 * teardown -- via the http_get() syscall. The response is written to a temp file
 * and opened in the Viewer.
 *
 *     URL -> http_get() -> /tmp/fetch.txt -> Viewer
 *
 * Client-side rendered into a shared surface, like the Viewer/Finder. No HTTPS,
 * no redirects, no HTML parsing: the raw HTTP response is shown as text. */
#include "libc.h"
#include "wm.h"
#include "keys.h"

#define DEF_W  440
#define DEF_H  180
#define URL_MAX 100
#define RESP_MAX 16384

static int wm, win, shm_id = -1;
static int S = 100;
static int W = DEF_W, H = DEF_H;
static gfx_surface_t surf;

static char url[URL_MAX + 1] = "example.com";
static int  url_len = 11;                 /* strlen("example.com") */
static char status[96] = "Enter a URL and click Fetch.";
static char resp[RESP_MAX];

static int sx(int v) { int r = v * S / 100; return r < 1 ? 1 : r; }

/* Fetch button rectangle (content-local), scaled. */
static int btn_x(void) { return sx(16); }
static int btn_y(void) { return sx(96); }
static int btn_w(void) { return sx(96); }
static int btn_h(void) { return sx(30); }

static void rect(int x, int y, int w, int h, uint32_t c) { gfx_fill_rect(&surf, x, y, w, h, c); }
static void text(int x, int y, const char *s, uint32_t c) { gfx_draw_text_s(&surf, x, y, s, c, S); }

static void present(void)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT; msgsend(wm, &r, sizeof(r));
}

static void redraw(void)
{
    rect(0, 0, W, H, GFX_RGB(0xf3, 0xf3, 0xf7));               /* window background */
    text(sx(16), sx(14), "Aurora Fetch", GFX_RGB(0x14, 0x14, 0x1c));
    text(sx(16), sx(36), "URL:", GFX_RGB(0x44, 0x44, 0x50));

    /* URL input box with the typed text + a caret. */
    int bx = sx(56), by = sx(32), bw = W - sx(72), bh = sx(24);
    rect(bx, by, bw, bh, GFX_RGB(0xff, 0xff, 0xff));
    rect(bx, by, bw, 1, GFX_RGB(0x99, 0x99, 0xa6));
    rect(bx, by + bh - 1, bw, 1, GFX_RGB(0x99, 0x99, 0xa6));
    rect(bx, by, 1, bh, GFX_RGB(0x99, 0x99, 0xa6));
    rect(bx + bw - 1, by, 1, bh, GFX_RGB(0x99, 0x99, 0xa6));
    char shown[URL_MAX + 2];
    int i = 0; for (; i < url_len; i++) shown[i] = url[i];
    shown[i++] = '_';                                          /* caret */
    shown[i] = '\0';
    text(bx + sx(6), by + sx(5), shown, GFX_RGB(0x10, 0x10, 0x18));

    /* Fetch button. */
    int hx = btn_x(), hy = btn_y(), hw = btn_w(), hh = btn_h();
    rect(hx, hy, hw, hh, GFX_RGB(0x33, 0x77, 0xff));
    text(hx + sx(24), hy + sx(8), "Fetch", GFX_RGB(0xff, 0xff, 0xff));

    /* Status line. */
    text(sx(16), sx(140), status, GFX_RGB(0x33, 0x33, 0x40));
    present();
}

static void set_status(const char *s)
{
    int i = 0; for (; s[i] && i < (int)sizeof(status) - 1; i++) status[i] = s[i];
    status[i] = '\0';
}

/* Append "label" + the URL into status (so the user sees what's happening). */
static void status_url(const char *label)
{
    int n = 0;
    for (int i = 0; label[i] && n < (int)sizeof(status) - 1; i++) status[n++] = label[i];
    for (int i = 0; i < url_len && n < (int)sizeof(status) - 1; i++) status[n++] = url[i];
    status[n] = '\0';
}

static void spawn_viewer(const char *path)
{
    int mid = fork();
    if (mid == 0) {
        char *argv[] = { "/disk/VIEWER.ELF", (char *)path, 0 };
        if (fork() == 0) { execv(argv[0], argv); _exit(127); }
        _exit(0);
    }
    int st; wait(&st);
}

static void do_fetch(void)
{
    if (url_len == 0) { set_status("Type a hostname first."); redraw(); return; }
    url[url_len] = '\0';

    status_url("Fetching http://");
    redraw();                                   /* shown while the syscall blocks */

    int n = http_get(url, resp, sizeof(resp));
    printf("[fetch] http_get(%s) = %d bytes\n", url, n);
    if (n == -1)      { set_status("No network. Boot Aurora with a NIC to fetch."); redraw(); return; }
    if (n == -2)      { status_url("DNS failed: ");        redraw(); return; }
    if (n == -3)      { status_url("Connection refused: "); redraw(); return; }
    if (n <= 0)       { set_status("No data received.");    redraw(); return; }

    int fd = open("/tmp/fetch.txt", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0)       { set_status("Fetched, but cannot write /tmp/fetch.txt"); redraw(); return; }
    write(fd, resp, n);
    close(fd);

    char msg[64]; int p = 0;
    const char *a = "Fetched ";
    for (int i = 0; a[i]; i++) msg[p++] = a[i];
    char tmp[12]; int v = n, q = 0;
    do { tmp[q++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (q > 0) msg[p++] = tmp[--q];
    const char *b = " bytes -> Viewer";
    for (int i = 0; b[i]; i++) msg[p++] = b[i];
    msg[p] = '\0';
    set_status(msg);
    redraw();
    spawn_viewer("/tmp/fetch.txt");
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "fetch: no window server\n"); return 1; }

    S = ui_scale();
    W = DEF_W * S / 100;
    H = DEF_H * S / 100;

    wm_req_t r; wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 300; r.y = 200; r.w = W; r.h = H;
    r.flags = WM_F_SHM;
    const char *title = "Aurora Fetch";
    for (int i = 0; title[i] && i < 47; i++) r.str[i] = title[i];
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0 || rep.shm < 0) { fprintf(2, "fetch: create failed\n"); return 1; }
    win = rep.win;

    void *px = shm_map(rep.shm);
    if (!px) { fprintf(2, "fetch: shm map failed\n"); return 1; }
    shm_id = rep.shm;
    surf.pixels = (uint8_t *)px;
    surf.width = W; surf.height = H; surf.pitch = W * 4; surf.bpp = 32;

    redraw();
    printf("[fetch] ready (pid %d), window %d\n", getpid(), win);

    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;

        if (ev.op == WM_DESTROY) { printf("[fetch] closed\n"); return 0; }

        if (ev.op == WM_SCALE) { S = ui_scale(); redraw(); continue; }

        if (ev.op == WM_POINTER) {
            static int prev;
            int press = (ev.w & 1) && !(prev & 1);
            prev = ev.w;
            if (press && ev.x >= btn_x() && ev.x < btn_x() + btn_w() &&
                ev.y >= btn_y() && ev.y < btn_y() + btn_h())
                do_fetch();
            continue;
        }

        if (ev.op != WM_KEY) continue;
        int c = ev.x;
        if (c == '\n' || c == '\r') { do_fetch(); continue; }
        if (c == 8 || c == 127) { if (url_len > 0) { url_len--; redraw(); } continue; }
        if (c >= 0x20 && c < 0x7f && url_len < URL_MAX) { url[url_len++] = (char)c; redraw(); }
    }
    return 0;
}
