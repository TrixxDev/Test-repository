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

/* Forked helper: blocks on the console keyboard and forwards each key to the
 * window server as a WM_KEY message, so the server's single event loop waits on
 * one source (its mailbox). */
static void keyboard_helper(int server_pid)
{
    char c;
    for (;;) {
        if (read(0, &c, 1) <= 0)
            continue;
        wm_req_t k;
        memset(&k, 0, sizeof(k));
        k.op = WM_KEY;
        k.x = (int)(unsigned char)c;
        msgsend(server_pid, &k, sizeof(k));
    }
}

/* Forked helper: blocks on the PS/2 mouse and forwards each pointer event to the
 * server as a WM_MOUSE message (same single-source event-loop model as keys). */
static void mouse_helper(int server_pid)
{
    int ev[3];                  /* {dx, dy, buttons} */
    for (;;) {
        if (mouse_read(ev) != 0)
            continue;
        wm_req_t m;
        memset(&m, 0, sizeof(m));
        m.op = WM_MOUSE;
        m.x = ev[0];            /* dx */
        m.y = ev[1];            /* dy */
        m.w = ev[2];            /* button bitmask */
        msgsend(server_pid, &m, sizeof(m));
    }
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (!fb_active()) {
        printf("[wm] no framebuffer; window server not started\n");
        return 0;
    }

    /* Fork the input helpers *before* mapping the framebuffer, so the children
     * don't inherit the large framebuffer mapping. */
    int server_pid = getpid();
    if (fork() == 0) {
        keyboard_helper(server_pid);
        _exit(0);
    }
    if (fork() == 0) {
        mouse_helper(server_pid);
        _exit(0);
    }

    unsigned info[3];
    void *fb = fb_map(info);
    if (!fb) {
        printf("[wm] framebuffer map failed\n");
        return 1;
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
    st.cursor_on = 1;                /* the windowserver owns the pointer */
    st.cursor_x = screen.width / 2;
    st.cursor_y = screen.height / 2;
    wm_present(&st, &screen);        /* paint the empty desktop + cursor right away */
    printf("[wm] ready (pid %d), framebuffer %ux%u pitch %u\n",
           getpid(), info[0], info[1], info[2]);

    /* Event loop: one source (the mailbox) carries app requests, keys and mouse. */
    int prev_buttons = 0;
    for (;;) {
        wm_req_t req;
        int from = -1;
        int n = msgrecv(&req, sizeof(req), &from);
        if (n < (int)sizeof(req))
            continue;

        switch (req.op) {
        case WM_CREATE: {
            void *px = malloc((size_t)req.w * req.h * 4);
            int id = px ? wm_create(&st, req.x, req.y, req.w, req.h, req.str, px, from) : -1;
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
        case WM_KEY: {
            /* Deliver the key to the focused window's app (full repaint is the
             * app's job via DRAW_* + PRESENT). */
            int owner = wm_focus_owner(&st);
            if (owner > 0)
                msgsend(owner, &req, sizeof(req));
            break;
        }
        case WM_MOUSE: {
            /* Move the cursor (clamped to the screen). On a left-button press,
             * raise the window under the pointer -> click-to-focus. Each event is
             * a full recomposite so the cursor and any z-change show at once. */
            st.cursor_x += req.x;
            st.cursor_y += req.y;
            if (st.cursor_x < 0) st.cursor_x = 0;
            if (st.cursor_y < 0) st.cursor_y = 0;
            if (st.cursor_x > screen.width - 1)  st.cursor_x = screen.width - 1;
            if (st.cursor_y > screen.height - 1) st.cursor_y = screen.height - 1;

            int buttons = req.w;
            if ((buttons & 1) && !(prev_buttons & 1)) {
                int id = wm_window_at(&st, st.cursor_x, st.cursor_y);
                if (id > 0)
                    wm_raise(&st, id);
            }
            prev_buttons = buttons;
            wm_present(&st, &screen);
            break;
        }
        default:
            break;
        }
    }
    return 0;
}
