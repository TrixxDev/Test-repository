/* windowserver: the AuroraOS userspace window server (Phase 9.2).
 *
 * A daemon like logger/netd. It maps the framebuffer (fb_map), keeps the window
 * list + z-order (wm_state, see wm.c), and serves the window IPC protocol from
 * apps: create/destroy/move windows, draw into a window's surface, and present
 * (composite the desktop + all windows to the screen). The kernel owns only the
 * framebuffer + IPC; all window policy lives here, in userspace.
 */
#include "libc.h"
#include "wm.h"

static wm_state_t   st;
static gfx_surface_t screen;

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    unsigned info[3];
    void *fb = fb_map(info);
    if (!fb) {
        /* Text mode (no framebuffer): nothing to serve, exit cleanly. */
        printf("[wm] no framebuffer; window server not started\n");
        return 0;
    }
    screen.pixels = fb;
    screen.width  = (int)info[0];
    screen.height = (int)info[1];
    screen.pitch  = (int)info[2];
    screen.bpp    = 32;

    if (svc_register(WM_SERVICE) != 0) {
        fprintf(2, "windowserver: failed to register\n");
        return 1;
    }
    wm_state_init(&st);
    wm_present(&st, &screen);        /* draw the empty desktop right away */
    printf("[wm] ready (pid %d), framebuffer %ux%u pitch %u\n",
           getpid(), info[0], info[1], info[2]);

    for (;;) {
        wm_req_t req;
        int from = -1;
        int n = msgrecv(&req, sizeof(req), &from);
        if (n < (int)sizeof(req))
            continue;

        switch (req.op) {
        case WM_CREATE: {
            void *px = malloc((size_t)req.w * req.h * 4);
            int id = px ? wm_create(&st, req.x, req.y, req.w, req.h, req.str, px) : -1;
            wm_rep_t rep = { id > 0 ? 0 : -1, id };
            msgsend(from, &rep, sizeof(rep));
            break;
        }
        case WM_DRAW_RECT:
            wm_draw_rect(&st, req.win, req.x, req.y, req.w, req.h, req.color);
            break;
        case WM_DRAW_TEXT:
            wm_draw_text(&st, req.win, req.x, req.y, req.str, req.color);
            break;
        case WM_MOVE:
            wm_move(&st, req.win, req.x, req.y);
            wm_present(&st, &screen);
            break;
        case WM_DESTROY:
            wm_destroy(&st, req.win);
            wm_present(&st, &screen);
            break;
        case WM_PRESENT:
            wm_present(&st, &screen);
            break;
        default:
            break;
        }
    }
    return 0;
}
