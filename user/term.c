/* Terminal.app: the first AuroraOS GUI app. Asks the window server for a window
 * and draws a (static) shell session into it. Demonstrates the multi-process
 * model: a separate process opening a real window via IPC. */
#include "libc.h"
#include "wm.h"

static void set_str(wm_req_t *r, const char *s)
{
    int i = 0;
    while (s[i] && i < 47) { r->str[i] = s[i]; i++; }
    r->str[i] = '\0';
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    /* The window server may still be starting; retry the lookup. */
    int wm = -1;
    for (int t = 0; t < 40 && wm < 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm < 0)
            for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm < 0) {
        fprintf(2, "term: no window server\n");
        return 1;
    }

    int W = 430, H = 200;
    wm_req_t r;
    wm_rep_t rep;

    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 300; r.y = 210; r.w = W; r.h = H;
    set_str(&r, "Terminal");
    msgsend(wm, &r, sizeof(r));

    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm)
            break;
    }
    if (rep.status != 0 || rep.win <= 0) {
        fprintf(2, "term: create failed\n");
        return 1;
    }
    int win = rep.win;

    /* Dark terminal background. */
    memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_RECT; r.win = win; r.x = 0; r.y = 0; r.w = W; r.h = H;
    r.color = GFX_RGB(0x1e, 0x1e, 0x28);
    msgsend(wm, &r, sizeof(r));

    /* A static shell session. */
    static const char *lines[] = {
        "AuroraOS Terminal", "aurora> id", "uid=1000 pid=9",
        "aurora> hello", "Hello AuroraOS", "aurora> _",
    };
    static const uint32_t col[] = {
        GFX_RGB(0xa8, 0xb0, 0xff), GFX_RGB(0x3a, 0xd0, 0x6a), GFX_RGB(0xe6, 0xe6, 0xee),
        GFX_RGB(0x3a, 0xd0, 0x6a), GFX_RGB(0xe6, 0xe6, 0xee), GFX_RGB(0x3a, 0xd0, 0x6a),
    };
    for (int i = 0; i < 6; i++) {
        memset(&r, 0, sizeof(r));
        r.op = WM_DRAW_TEXT; r.win = win; r.x = 12; r.y = 14 + i * 20; r.color = col[i];
        set_str(&r, lines[i]);
        msgsend(wm, &r, sizeof(r));
    }

    memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT;
    msgsend(wm, &r, sizeof(r));

    printf("[term] opened window %d\n", win);
    return 0;       /* the window persists in the server */
}
