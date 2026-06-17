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
#include "desktop.h"

static wm_state_t   st;
static gfx_surface_t screen;    /* the live framebuffer (slow VRAM) */
static gfx_surface_t back;      /* off-screen scene, no cursor (fast RAM)  */
static gfx_surface_t bg;        /* cached static background: wallpaper + menu bar */
static int           dock_win = -1;   /* the borderless Dock window, if any */

/* Drag state: set when the user presses the left button inside a title bar, and
 * cleared on release. While active, each pointer motion re-places the window so
 * that the grabbed point stays under the cursor (offset bookkeeping). */
typedef struct {
    int active;
    int window_id;
    int offset_x, offset_y;     /* cursor-to-window-origin offset at grab time */
} drag_state_t;

/* ---- Aurora system menu (chrome, owned by the windowserver) ---------------
 *
 * The menu bar's "Aurora" title is the entry point for system actions. It lives
 * in the windowserver (not a separate process) so it works even if the Dock or
 * an app has died; the actions themselves launch ordinary processes. */
#define MENUBAR_H    28             /* matches kernel/desktop.c MENUBAR_H */
#define AURORA_X0    8
#define AURORA_X1    96
#define MENU_X       8
#define MENU_Y       MENUBAR_H
#define MENU_W       200
#define MENU_ITEM_H  26
#define MENU_PAD     6
#define MENU_N       4
#define MENU_H       (MENU_N * MENU_ITEM_H + 2 * MENU_PAD)

static int menu_open  = 0;
static int menu_hover = -1;

/* ---- theme settings (/disk/settings.cfg) ---- */
static const char *const WP_NAMES[4] = { "blue", "dark", "purple", "green" };
static const char *const AC_NAMES[4] = { "blue", "orange", "purple", "green" };

static int cfg_value(const char *buf, const char *key, char *out, int cap)
{
    int klen = (int)strlen(key);
    for (const char *p = buf; *p; ) {
        if (strncmp(p, key, (size_t)klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            int i = 0;
            while (v[i] && v[i] != '\n' && v[i] != '\r' && i < cap - 1) { out[i] = v[i]; i++; }
            out[i] = '\0';
            return 1;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return 0;
}

static int cfg_map(const char *v, const char *const *names, int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(v, names[i]) == 0) return i;
    return 0;                               /* default to index 0 */
}

/* Read /disk/settings.cfg and apply the wallpaper + accent theme. */
static void load_settings(void)
{
    int wp = 0, ac = 0;
    int fd = open("/disk/settings.cfg", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char val[16];
            if (cfg_value(buf, "wallpaper", val, sizeof(val))) wp = cfg_map(val, WP_NAMES, 4);
            if (cfg_value(buf, "accent",    val, sizeof(val))) ac = cfg_map(val, AC_NAMES, 4);
        }
    }
    desktop_set_theme(wp, ac);
}

static const char *menu_items[MENU_N] = {
    "About AuroraOS",
    "Settings...",
    "Close All Windows",
    "Shut Down",
};

static int in_aurora_menu(int x, int y)
{
    return x >= AURORA_X0 && x < AURORA_X1 && y >= 0 && y < MENUBAR_H;
}

static int menu_item_at(int x, int y)   /* item under (x,y) while open, or -1 */
{
    if (!menu_open) return -1;
    if (x < MENU_X || x >= MENU_X + MENU_W) return -1;
    if (y < MENU_Y + MENU_PAD || y >= MENU_Y + MENU_H - MENU_PAD) return -1;
    int item = (y - MENU_Y - MENU_PAD) / MENU_ITEM_H;
    return (item >= 0 && item < MENU_N) ? item : -1;
}

static void draw_menu(gfx_surface_t *dst)
{
    if (!menu_open) return;
    uint32_t accent = desktop_accent_color();
    /* Highlight the Aurora title in the bar (theme accent). */
    gfx_fill_rect(dst, AURORA_X0, 0, AURORA_X1 - AURORA_X0, MENUBAR_H, accent);
    gfx_fill_round_rect(dst, 12, 6, 16, 16, 4, GFX_RGB(0xff, 0xff, 0xff));
    gfx_draw_text(dst, 36, 6, "Aurora", GFX_RGB(0xff, 0xff, 0xff));
    /* Dropdown: a hard shadow, then a light rounded panel with the items. */
    gfx_fill_round_rect(dst, MENU_X + 3, MENU_Y + 3, MENU_W, MENU_H, 8, GFX_RGB(0x12, 0x12, 0x1a));
    gfx_fill_round_rect(dst, MENU_X, MENU_Y, MENU_W, MENU_H, 8, GFX_RGB(0xf6, 0xf6, 0xfa));
    for (int i = 0; i < MENU_N; i++) {
        int iy = MENU_Y + MENU_PAD + i * MENU_ITEM_H;
        uint32_t fg = GFX_RGB(0x22, 0x22, 0x2a);
        if (i == menu_hover) {
            gfx_fill_rect(dst, MENU_X + 3, iy, MENU_W - 6, MENU_ITEM_H, accent);
            fg = GFX_RGB(0xff, 0xff, 0xff);
        }
        gfx_draw_text(dst, MENU_X + 14, iy + (MENU_ITEM_H - 16) / 2, menu_items[i], fg);
    }
}

/* ---- damage-driven presentation -------------------------------------------
 *
 * The old code recomposited the entire desktop straight into the framebuffer on
 * every event, so a single mouse step repainted ~3 MB of VRAM (slow + flicker).
 * Instead we composite the scene once into an off-screen back buffer (RAM) and
 * copy only the changed rectangles to the framebuffer, overlaying the cursor as
 * we go. Pure pointer motion never touches the scene at all — it just restores
 * the few pixels under the old cursor and redraws it at the new spot.
 */

/* Render the static background (wallpaper + menu bar) into the cache. It is
 * expensive to compute (a full-screen per-pixel gradient) but cheap to blit, so
 * we build it once at startup and again only when the theme changes — never on a
 * per-frame basis the way the old code recomputed the gradient on every event. */
static void rebuild_bg(void)
{
    desktop_render(&bg);
}

/* Rebuild the off-screen scene (background + windows + open menu, no cursor).
 * The background is copied from the cache instead of recomputing the gradient.
 * Call only when the scene actually changes. */
static void compose(void)
{
    memcpy(back.pixels, bg.pixels, (size_t)back.pitch * back.height);
    wm_composite_windows(&st, &back);
    draw_menu(&back);
}

/* Like compose(), but only refreshes the background within (rx,ry,rw,rh) before
 * redrawing the windows — used during a drag so a step costs O(damage) instead
 * of O(screen). Windows are redrawn in full (idempotent outside the rect: the
 * scene there is unchanged, so the cached back buffer stays correct); since only
 * the damage rect is later flushed, the result there is identical to compose(). */
static void compose_dmg(int rx, int ry, int rw, int rh)
{
    if (rx < 0) { rw += rx; rx = 0; }
    if (ry < 0) { rh += ry; ry = 0; }
    if (rx + rw > back.width)  rw = back.width  - rx;
    if (ry + rh > back.height) rh = back.height - ry;
    if (rw <= 0 || rh <= 0)
        return;
    for (int y = 0; y < rh; y++) {
        uint8_t *d = back.pixels + (uint32_t)(ry + y) * back.pitch + (uint32_t)rx * 4;
        uint8_t *s = bg.pixels   + (uint32_t)(ry + y) * bg.pitch   + (uint32_t)rx * 4;
        memcpy(d, s, (size_t)rw * 4);
    }
    wm_composite_windows(&st, &back);
    draw_menu(&back);
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

/* Launch a program detached (double-fork so it reparents to init for reaping). */
static void wm_spawn(char **argv)
{
    int mid = fork();
    if (mid == 0) {
        if (fork() == 0) { execv(argv[0], argv); _exit(127); }
        _exit(0);
    }
    int s; wait(&s);                    /* reap the middle child */
}

/* Draw a final screen and power off (the kernel halts; windowserver is root). */
static void do_shutdown(void)
{
    gfx_fill_rect(&screen, 0, 0, screen.width, screen.height, GFX_RGB(0x10, 0x12, 0x18));
    const char *msg = "It is now safe to power off AuroraOS.";
    int tw = gfx_text_width(msg);
    gfx_draw_text(&screen, (screen.width - tw) / 2, screen.height / 2 - 8, msg,
                  GFX_RGB(0xe8, 0xe8, 0xf2));
    halt();                             /* no return */
}

/* Run an Aurora-menu item. (0) About -> Viewer on ABOUT.TXT, (1) Settings,
 * (2) close every window but the Dock, (3) shut down. */
static void menu_action(int item)
{
    if (item == 0) {
        char *argv[] = { "/disk/VIEWER.ELF", "/disk/ABOUT.TXT", 0 };
        wm_spawn(argv);
    } else if (item == 1) {
        char *argv[] = { "/disk/SETTINGS.ELF", 0 };
        wm_spawn(argv);
    } else if (item == 2) {
        int id;
        while ((id = wm_first_window_except(&st, dock_win)) > 0) {
            int owner = wm_owner_of(&st, id);
            destroy_window(id);
            if (owner > 0) {            /* ask the app to exit too */
                wm_req_t bye;
                memset(&bye, 0, sizeof(bye));
                bye.op = WM_DESTROY; bye.win = id;
                msgsend(owner, &bye, sizeof(bye));
            }
        }
    } else if (item == 3) {
        do_shutdown();                  /* no return */
    }
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

    /* Cached static background (same geometry): built once, blitted every frame. */
    bg.width  = screen.width;
    bg.height = screen.height;
    bg.pitch  = screen.width * 4;
    bg.bpp    = 32;
    bg.pixels = malloc((size_t)bg.pitch * bg.height);
    if (!bg.pixels) {
        printf("[wm] background cache alloc failed\n");
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
    load_settings();                 /* apply the saved wallpaper + accent theme */
    rebuild_bg();                    /* render the static background into the cache */
    compose();                       /* build the empty desktop in the back buffer */
    flush(0, 0, screen.width, screen.height);   /* push it (with cursor) once */
    printf("[wm] ready (pid %d), framebuffer %ux%u pitch %u\n",
           getpid(), info[0], info[1], info[2]);

    /* Event loop: one source (the mailbox) carries app requests, keys and mouse.
     *
     * The PS/2 mouse can emit ~200 events/s, but the compositor only needs to
     * paint as fast as it can. So when a WM_MOUSE arrives we drain the mailbox
     * (non-blocking) and *coalesce* consecutive same-button motion into a single
     * event — summing the deltas — before doing one recomposite. This caps the
     * compose/flush rate at the server's render throughput instead of the packet
     * rate. Button *edges* (press/release) and non-mouse messages break the run
     * so clicks are never merged away; the message that broke it is stashed and
     * handled on the next iteration (with its original sender preserved). */
    int prev_buttons = 0;
    drag_state_t drag = { 0, 0, 0, 0 };
    wm_req_t stash; int have_stash = 0, stash_from = -1;
    for (;;) {
        wm_req_t req;
        int from = -1;
        if (have_stash) {
            req = stash; from = stash_from; have_stash = 0;
        } else {
            int n = msgrecv(&req, sizeof(req), &from);
            if (n < (int)sizeof(req))
                continue;
        }

        if (req.op == WM_MOUSE) {
            for (;;) {
                wm_req_t nx; int nf = -1;
                int n2 = msgrecv_nb(&nx, sizeof(nx), &nf);
                if (n2 < (int)sizeof(nx))
                    break;                  /* mailbox empty (or short): stop */
                if (nx.op == WM_MOUSE && nx.w == req.w) {
                    req.x += nx.x;          /* same buttons: merge the motion */
                    req.y += nx.y;
                    continue;
                }
                stash = nx; stash_from = nf; have_stash = 1;  /* handle next */
                break;
            }
        }

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
        case WM_RELOAD_SETTINGS:
            /* Settings changed /disk/settings.cfg: re-apply the theme + repaint.
             * The wallpaper/accent may have changed, so refresh the cache too. */
            load_settings();
            rebuild_bg();
            compose();
            flush(0, 0, screen.width, screen.height);
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

            int full_redraw = 0;        /* menu open/close/hover -> recompose all */

            /* --- Aurora system menu (chrome, above every window) --- */
            int menu_consumed = 0;
            if (press && in_aurora_menu(st.cursor_x, st.cursor_y)) {
                menu_open = !menu_open;          /* toggle the dropdown */
                menu_hover = -1;
                full_redraw = 1; menu_consumed = 1;
            } else if (press && menu_open) {
                int item = menu_item_at(st.cursor_x, st.cursor_y);
                menu_open = 0; menu_hover = -1;  /* any click closes the menu */
                full_redraw = 1; menu_consumed = 1;
                if (item >= 0)
                    menu_action(item);           /* may not return (Shut Down) */
            }
            if (menu_open && !menu_consumed) {   /* hover highlight while open */
                int nh = menu_item_at(st.cursor_x, st.cursor_y);
                if (nh != menu_hover) { menu_hover = nh; full_redraw = 1; }
            }

            /* Topmost window under the pointer (may be the borderless Dock). */
            int hit = wm_window_at(&st, st.cursor_x, st.cursor_y);

            /* Chrome interactions (raise / drag / close) apply only to ordinary
             * decorated windows; the Dock just receives the pointer event below.
             * Skipped when the menu consumed the click. */
            if (press && !menu_consumed && hit > 0 && wm_is_decorated(&st, hit)) {
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

            if (full_redraw) {
                /* Menu opened/closed/hovered (or it changed the scene): recompose
                 * the whole screen so the dropdown appears/clears cleanly. */
                compose();
                flush(0, 0, screen.width, screen.height);
            } else {
                if (scene_changed)
                    compose_dmg(dmg_x, dmg_y, dmg_w, dmg_h);
                /* Erase the old cursor, push any scene damage, draw the new
                 * cursor. Each flush re-overlays the pointer where it intersects. */
                flush(old_cx, old_cy, WM_CURSOR_W, WM_CURSOR_H);
                if (scene_changed)
                    flush(dmg_x, dmg_y, dmg_w, dmg_h);
                flush(st.cursor_x, st.cursor_y, WM_CURSOR_W, WM_CURSOR_H);
            }
            #undef ADD_DMG

            /* Forward the pointer to the app under it (in content-local coords),
             * unless a window is being dragged (the cursor is captured then).
             * The Dock uses this for hover + click; ordinary apps may ignore it.
             * If that app is dead, deliver() reaps its window (e.g. a killed Dock
             * vanishes the next time the cursor passes over where it was).
             * Skipped when the menu consumed this click. */
            if (hit > 0 && !drag.active && !menu_consumed) {
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
