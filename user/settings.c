/* Settings.app: a placeholder for the AuroraOS settings (Phase 10.2). For now it
 * is a smoke-test target launched from the Aurora system menu — a real window
 * with a sidebar of (inert) categories. 10.3 will fill the panes in. */
#include "libc.h"
#include "wm.h"

#define W 420
#define H 280

static int wm;
static int win;

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

static void redraw(void)
{
    rect(0, 0, W, H, GFX_RGB(0xf6, 0xf6, 0xf9));
    rect(0, 0, 120, H, GFX_RGB(0xec, 0xec, 0xf1));     /* sidebar */
    rect(120, 0, 1, H, GFX_RGB(0xd5, 0xd5, 0xdc));
    text(16, 16, "Desktop",  GFX_RGB(0x22, 0x22, 0x2a));
    text(16, 40, "System",   GFX_RGB(0x22, 0x22, 0x2a));

    text(140, 16, "Settings", GFX_RGB(0x11, 0x11, 0x18));
    text(140, 52, "Desktop and System preferences",  GFX_RGB(0x55, 0x55, 0x60));
    text(140, 76, "will appear here (Phase 10.3).",   GFX_RGB(0x55, 0x55, 0x60));

    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT; msgsend(wm, &r, sizeof(r));
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "settings: no window server\n"); return 1; }

    wm_req_t r; wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 320; r.y = 200; r.w = W; r.h = H;
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

    for (;;) {
        wm_req_t ev;
        int n = msgrecv(&ev, sizeof(ev), &from);
        if (n < (int)sizeof(ev)) continue;
        if (ev.op == WM_DESTROY) { printf("[settings] closed\n"); return 0; }
        /* pointer/keys ignored for now */
    }
    return 0;
}
