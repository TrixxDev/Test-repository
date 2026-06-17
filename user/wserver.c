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
static gfx_surface_t screen;    /* the live framebuffer (slow VRAM) */
static gfx_surface_t back;      /* off-screen scene, no cursor (fast RAM)  */
static int           dock_win = -1;   /* the borderless Dock window, if any */

/* Drag state: set when the user presses the left button inside a title bar, and
 * cleared on release. While active, each pointer motion re-places the window so
 * that the grabbed point stays under the cursor (offset bookkeeping). */
typedef struct {
    int active;
    int window_id;
    int offset_x, offset_y;     /* cursor-to-window-origin offset at grab time */
} drag_state_t;

/* ---- damage-driven presentation -------------------------------------------
 *
 * The old code recomposited the entire desktop straight into the framebuffer on
 * every event, so a single mouse step repainted ~3 MB of VRAM (slow + flicker).
 * Instead we composite the scene once into an off-screen back buffer (RAM) and
 * copy only the changed rectangles to the framebuffer, overlaying the cursor as
 * we go. Pure pointer motion never touches the scene at all — it just restores
 * the few pixels under the old cursor and redraws it at the new spot.
 */

/* Rebuild the off-screen scene (desktop + windows, no cursor). Call only when
 * the scene actually changes (window drawn/moved/created/destroyed/raised). */
static void compose(void)
{
    wm_compose(&st, &back);
}

static int cursor_visible(void)
{
    return st.cursor_on;
}

/* Copy rectangle (rx,ry,rw,rh) from the back buffer to the framebuffer, then
 * overlay the cursor if it intersects the rectangle. Clipped to the screen. */
static void flush(int rx, int ry, int rw, int rh)
{
    if (rx < 0) { rw += rx; rx = 0; }
    if (ry < 0) { rh += ry; ry = 0; }
    if (rx + rw > screen.width)  rw = screen.width  - rx;
    if (ry + rh > screen.height) rh = screen.height - ry;
    if (rw <= 0 || rh <= 0)
        return;

    for (int y = 0; y < rh; y++) {
        uint8_t *dst = screen.pixels + (uint32_t)(ry + y) * screen.pitch + (uint32_t)rx * 4;
        uint8_t *src = back.pixels   + (uint32_t)(ry + y) * back.pitch   + (uint32_t)rx * 4;
        memcpy(dst, src, (size_t)rw * 4);
    }

    if (cursor_visible() &&
        st.cursor_x < rx + rw && st.cursor_x + WM_CURSOR_W > rx &&
        st.cursor_y < ry + rh && st.cursor_y + WM_CURSOR_H > ry)
        wm_draw_cursor(&screen, st.cursor_x, st.cursor_y);
}

/* Refresh just window `id`'s footprint (content + title bar + shadow). */
static void flush_window(int id)
{
    int x, y, w, h;
    if (wm_window_bounds(&st, id, &x, &y, &w, &h))
        flush(x, y, w, h);
}

/* Destroy a window and free the content buffer the server malloc'd for it, so
 * opening and closing windows leaks no memory. */
static void destroy_window(int id)
{
    void *px = wm_content_ptr(&st, id);
    wm_destroy(&st, id);
    if (px)
        free(px);
    if (id == dock_win)
        dock_win = -1;
}

/* Remove every window owned by `pid` (used when an app dies). Returns 1 if any
 * were removed, so the caller knows to recomposite. */
static int reap_owner(int pid)
{
    int reaped = 0, id;
    while ((id = wm_window_of_owner(&st, pid)) > 0) {
        destroy_window(id);
        reaped = 1;
    }
    return reaped;
}

/* Deliver `msg` to an app. If the send fails *because the app is gone* (not just
 * a momentarily full mailbox — distinguished with uid_of), reap its windows so a
 * crashed/closed Dock/Finder/Terminal never leaves a ghost on screen. Returns 1
 * if a reap happened (caller should recomposite + flush). */
static int deliver(int owner, const void *msg, int len)
{
    if (owner <= 0)
        return 0;
    if (msgsend(owner, msg, len) == 0)
        return 0;                       /* delivered */
    if (uid_of(owner) >= 0)
        return 0;                       /* alive: mailbox full, message dropped */
    return reap_owner(owner);           /* dead: clean up its windows */
}

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

    /* Off-screen scene buffer (packed, same dimensions as the framebuffer). The
     * compositor renders here; only changed rectangles are copied to VRAM. */
    back.width  = screen.width;
    back.height = screen.height;
    back.pitch  = screen.width * 4;
    back.bpp    = 32;
    back.pixels = malloc((size_t)back.pitch * back.height);
    if (!back.pixels) {
        printf("[wm] back buffer alloc failed\n");
        return 1;
    }

    if (svc_register(WM_SERVICE) != 0) {
        fprintf(2, "windowserver: failed to register\n");
        return 1;
    }
    wm_state_init(&st);
    st.cursor_on = 1;                /* the windowserver owns the pointer */
    st.cursor_x = screen.width / 2;
    st.cursor_y = screen.height / 2;
    compose();                       /* build the empty desktop in the back buffer */
    flush(0, 0, screen.width, screen.height);   /* push it (with cursor) once */
    printf("[wm] ready (pid %d), framebuffer %ux%u pitch %u\n",
           getpid(), info[0], info[1], info[2]);

    /* Event loop: one source (the mailbox) carries app requests, keys and mouse. */
    int prev_buttons = 0;
    drag_state_t drag = { 0, 0, 0, 0 };
    for (;;) {
        wm_req_t req;
        int from = -1;
        int n = msgrecv(&req, sizeof(req), &from);
        if (n < (int)sizeof(req))
            continue;

        switch (req.op) {
        case WM_CREATE: {
            int dock = (req.flags & WM_F_DOCK) != 0;
            int x = req.x, y = req.y;
            if (dock) {                 /* pin the Dock to the bottom-center */
                x = (screen.width  - req.w) / 2;
                y =  screen.height - req.h - 16;
            }
            int resizable = (req.flags & WM_F_RESIZABLE) != 0;
            void *px = (req.w > 0 && req.h > 0) ? malloc((size_t)req.w * req.h * 4) : 0;
            int id = px ? wm_create(&st, x, y, req.w, req.h, req.str, px, from, !dock, resizable) : -1;
            if (id <= 0 && px)
                free(px);               /* slot full / bad size: don't leak the buffer */
            if (id > 0 && dock) {
                wm_set_top(&st, id);    /* the Dock floats above ordinary windows */
                dock_win = id;
            }
            wm_rep_t rep = { id > 0 ? 0 : -1, id };
            msgsend(from, &rep, sizeof(rep));
            break;
        }
        case WM_DRAW_RECT:
            wm_draw_rect(&st, req.win, req.x, req.y, req.w, req.h, req.color);
            break;
        case WM_DRAW_ROUND_RECT:
            wm_draw_round_rect(&st, req.win, req.x, req.y, req.w, req.h, req.flags, req.color);
            break;
        case WM_DRAW_TEXT:
            wm_draw_text(&st, req.win, req.x, req.y, req.str, req.color);
            break;
        case WM_MOVE: {
            /* Damage = where the window was plus where it lands. */
            int ox, oy, ow, oh;
            int had = wm_window_bounds(&st, req.win, &ox, &oy, &ow, &oh);
            wm_move(&st, req.win, req.x, req.y);
            compose();
            if (had)
                flush(ox, oy, ow, oh);
            flush_window(req.win);
            break;
        }
        case WM_DESTROY: {
            if (wm_owner_of(&st, req.win) != from)
                break;                   /* an app may only destroy its own window */
            int ox, oy, ow, oh;
            int had = wm_window_bounds(&st, req.win, &ox, &oy, &ow, &oh);
            destroy_window(req.win);     /* frees the content buffer too */
            compose();
            if (had)
                flush(ox, oy, ow, oh);   /* reveal whatever was behind it */
            break;
        }
        case WM_PRESENT: {
            /* The app just finished redrawing its surface; refresh only that
             * window's footprint instead of the whole screen. */
            int id = wm_window_of_owner(&st, from);
            compose();
            if (id > 0)
                flush_window(id);
            else
                flush(0, 0, screen.width, screen.height);
            break;
        }
        case WM_KEY: {
            /* Deliver the key to the focused window's app (full repaint is the
             * app's job via DRAW_* + PRESENT). If that app turns out to be dead,
             * deliver() reaps its window(s) and we recomposite. */
            int owner = wm_focus_owner(&st);
            if (deliver(owner, &req, sizeof(req))) {
                compose();
                flush(0, 0, screen.width, screen.height);
            }
            break;
        }
        case WM_STAT:
            /* Diagnostics: live-window count + heap top, for leak/stress checks. */
            printf("[wm] stat: live=%d brk=0x%x\n",
                   wm_window_count(&st), (unsigned)(uintptr_t)sbrk(0));
            break;
        case WM_MOUSE: {
            /* Move the cursor, then run the pointer state machine. The scene only
             * needs recompositing when it actually changes (raise, close, drag);
             * a plain move just restores the pixels under the old cursor and
             * redraws the pointer at its new spot — no full repaint. */
            int old_cx = st.cursor_x, old_cy = st.cursor_y;
            st.cursor_x += req.x;
            st.cursor_y += req.y;
            if (st.cursor_x < 0) st.cursor_x = 0;
            if (st.cursor_y < 0) st.cursor_y = 0;
            if (st.cursor_x > screen.width - 1)  st.cursor_x = screen.width - 1;
            if (st.cursor_y > screen.height - 1) st.cursor_y = screen.height - 1;

            int buttons = req.w;
            int press   =  (buttons & 1) && !(prev_buttons & 1);
            int release = !(buttons & 1) &&  (prev_buttons & 1);

            int scene_changed = 0;
            /* Bounding box of any scene damage (window raised/closed/moved). */
            int dmg_x = 0, dmg_y = 0, dmg_w = 0, dmg_h = 0;
            #define ADD_DMG(x, y, w, h) do {                                  \
                if (!scene_changed) { dmg_x = (x); dmg_y = (y);               \
                    dmg_w = (w); dmg_h = (h); }                               \
                else {                                                        \
                    int x0 = dmg_x < (x) ? dmg_x : (x);                       \
                    int y0 = dmg_y < (y) ? dmg_y : (y);                       \
                    int x1 = dmg_x + dmg_w > (x) + (w) ? dmg_x + dmg_w : (x) + (w); \
                    int y1 = dmg_y + dmg_h > (y) + (h) ? dmg_y + dmg_h : (y) + (h); \
                    dmg_x = x0; dmg_y = y0; dmg_w = x1 - x0; dmg_h = y1 - y0; \
                }                                                             \
                scene_changed = 1;                                           \
            } while (0)

            /* Topmost window under the pointer (may be the borderless Dock). */
            int hit = wm_window_at(&st, st.cursor_x, st.cursor_y);

            /* Chrome interactions (raise / drag / close) apply only to ordinary
             * decorated windows; the Dock just receives the pointer event below. */
            if (press && hit > 0 && wm_is_decorated(&st, hit)) {
                int id = hit, cx = st.cursor_x, cy = st.cursor_y;
                wm_raise(&st, id);                  /* click-to-focus first */

                int bx, by, bw, bh;                 /* footprint before any change */
                if (wm_window_bounds(&st, id, &bx, &by, &bw, &bh))
                    ADD_DMG(bx, by, bw, bh);

                if (wm_in_close_button(&st, id, cx, cy)) {
                    int owner = wm_owner_of(&st, id);
                    destroy_window(id);             /* frees the content buffer too */
                    if (owner > 0) {                /* tell the app to exit */
                        wm_req_t bye;
                        memset(&bye, 0, sizeof(bye));
                        bye.op = WM_DESTROY; bye.win = id;
                        msgsend(owner, &bye, sizeof(bye));
                    }
                } else if (wm_in_min_button(&st, id, cx, cy)) {
                    wm_toggle_shade(&st, id);       /* window-shade collapse/expand */
                    if (wm_window_bounds(&st, id, &bx, &by, &bw, &bh))
                        ADD_DMG(bx, by, bw, bh);
                } else if (wm_in_max_button(&st, id, cx, cy)) {
                    int nw, nh;                     /* maximize/restore: resize the surface */
                    if (wm_toggle_max(&st, id, screen.width, screen.height, &nw, &nh)) {
                        void *npx = malloc((size_t)nw * nh * 4);
                        if (npx) {
                            memset(npx, 0, (size_t)nw * nh * 4);
                            void *old = wm_content_ptr(&st, id);
                            wm_set_content(&st, id, npx, nw, nh);
                            if (old) free(old);
                            int owner = wm_owner_of(&st, id);
                            if (owner > 0) {        /* ask the app to redraw at the new size */
                                wm_req_t rz;
                                memset(&rz, 0, sizeof(rz));
                                rz.op = WM_RESIZE; rz.win = id; rz.w = nw; rz.h = nh;
                                msgsend(owner, &rz, sizeof(rz));
                            }
                        }
                    }
                    if (wm_window_bounds(&st, id, &bx, &by, &bw, &bh))
                        ADD_DMG(bx, by, bw, bh);
                } else if (wm_in_titlebar(&st, id, cx, cy)) {
                    drag.active   = 1;
                    drag.window_id = id;
                    drag.offset_x = cx - wm_window_x(&st, id);
                    drag.offset_y = cy - wm_window_y(&st, id);
                }
            }

            if (drag.active && (buttons & 1)) {
                int ox, oy, ow, oh;                /* old footprint */
                int had = wm_window_bounds(&st, drag.window_id, &ox, &oy, &ow, &oh);
                wm_move_clamped(&st, drag.window_id,
                                st.cursor_x - drag.offset_x,
                                st.cursor_y - drag.offset_y,
                                screen.width, screen.height);
                if (had)
                    ADD_DMG(ox, oy, ow, oh);
                int nx, ny, nw, nh;                /* new footprint */
                if (wm_window_bounds(&st, drag.window_id, &nx, &ny, &nw, &nh))
                    ADD_DMG(nx, ny, nw, nh);
            }

            if (release)
                drag.active = 0;

            prev_buttons = buttons;

            if (scene_changed)
                compose();
            /* Erase the old cursor, push any scene damage, draw the new cursor.
             * Each flush re-overlays the pointer where it intersects. */
            flush(old_cx, old_cy, WM_CURSOR_W, WM_CURSOR_H);
            if (scene_changed)
                flush(dmg_x, dmg_y, dmg_w, dmg_h);
            flush(st.cursor_x, st.cursor_y, WM_CURSOR_W, WM_CURSOR_H);
            #undef ADD_DMG

            /* Forward the pointer to the app under it (in content-local coords),
             * unless a window is being dragged (the cursor is captured then).
             * The Dock uses this for hover + click; ordinary apps may ignore it.
             * If that app is dead, deliver() reaps its window (e.g. a killed Dock
             * vanishes the next time the cursor passes over where it was). */
            if (hit > 0 && !drag.active) {
                int ox, oy;
                if (wm_content_origin(&st, hit, &ox, &oy)) {
                    wm_req_t pe;
                    memset(&pe, 0, sizeof(pe));
                    pe.op  = WM_POINTER;
                    pe.win = hit;
                    pe.x   = st.cursor_x - ox;
                    pe.y   = st.cursor_y - oy;
                    pe.w   = buttons;
                    if (deliver(wm_owner_of(&st, hit), &pe, sizeof(pe))) {
                        compose();
                        flush(0, 0, screen.width, screen.height);
                    }
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return 0;
}
