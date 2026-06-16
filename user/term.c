/* Terminal.app: the first interactive AuroraOS GUI app. It asks the window
 * server for a window, then runs an event loop: keys forwarded by the window
 * server are echoed into a tiny shell-style transcript, and the window is
 * redrawn (full repaint) after each keystroke. Demonstrates the closed loop
 * keyboard -> windowserver -> app -> redraw -> framebuffer. */
#include "libc.h"
#include "wm.h"

#define W 460
#define H 240
#define COLS 56
#define ROWS 9

static int wm;
static int win;
static char hist[ROWS][COLS];
static int  nhist;
static char input[COLS];
static int  ilen;

static void set_str(wm_req_t *r, const char *s)
{
    int i = 0;
    while (s[i] && i < 47) { r->str[i] = s[i]; i++; }
    r->str[i] = '\0';
}

static void draw_text(int x, int y, const char *s, uint32_t color)
{
    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_TEXT; r.win = win; r.x = x; r.y = y; r.color = color;
    set_str(&r, s);
    msgsend(wm, &r, sizeof(r));
}

static void repaint(void)
{
    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_RECT; r.win = win; r.x = 0; r.y = 0; r.w = W; r.h = H;
    r.color = GFX_RGB(0x1e, 0x1e, 0x28);
    msgsend(wm, &r, sizeof(r));

    draw_text(12, 12, "AuroraOS Terminal", GFX_RGB(0xa8, 0xb0, 0xff));
    for (int i = 0; i < nhist; i++)
        draw_text(12, 40 + i * 18, hist[i], GFX_RGB(0xe6, 0xe6, 0xee));

    char line[COLS + 10];
    int p = 0;
    const char *prompt = "aurora> ";
    while (prompt[p]) { line[p] = prompt[p]; p++; }
    for (int i = 0; i < ilen && p < COLS + 8; i++) line[p++] = input[i];
    line[p++] = '_';
    line[p] = '\0';
    draw_text(12, 40 + nhist * 18, line, GFX_RGB(0x3a, 0xd0, 0x6a));

    memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT;
    msgsend(wm, &r, sizeof(r));
}

static void commit_line(void)
{
    if (nhist >= ROWS - 1) {                 /* scroll up one line */
        for (int i = 0; i < ROWS - 1; i++)
            memcpy(hist[i], hist[i + 1], COLS);
        nhist = ROWS - 2;
    }
    char *h = hist[nhist++];
    int p = 0;
    const char *prompt = "aurora> ";
    while (prompt[p] && p < COLS - 1) { h[p] = prompt[p]; p++; }
    for (int i = 0; i < ilen && p < COLS - 1; i++) h[p++] = input[i];
    h[p] = '\0';
    ilen = 0;
}

static int parse_int(const char *s)
{
    int v = 0, sign = 1;
    if (*s == '-') { sign = -1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v * sign;
}

int main(int argc, char **argv)
{
    /* Optional: argv = {prog, x, y, title}. Lets init stagger several windows. */
    int wx = 280, wy = 190;
    const char *title = "Terminal";
    if (argc > 2) { wx = parse_int(argv[1]); wy = parse_int(argv[2]); }
    if (argc > 3) title = argv[3];

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0)
            for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "term: no window server\n"); return 1; }

    wm_req_t r;
    wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = wx; r.y = wy; r.w = W; r.h = H;
    set_str(&r, title);
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0) { fprintf(2, "term: create failed\n"); return 1; }
    win = rep.win;

    repaint();
    printf("[term] opened window %d\n", win);

    /* Event loop: keys arrive (forwarded by the window server) as WM_KEY. */
    for (;;) {
        wm_req_t k;
        int n = msgrecv(&k, sizeof(k), &from);
        if (n < (int)sizeof(k) || k.op != WM_KEY)
            continue;
        int c = k.x;
        if (c == '\n' || c == '\r')      commit_line();
        else if (c == '\b')              { if (ilen > 0) ilen--; }
        else if (c >= 32 && c < 127 && ilen < COLS - 10) input[ilen++] = (char)c;
        repaint();
    }
    return 0;
}
