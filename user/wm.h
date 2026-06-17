/* AuroraOS window model + compositor + window-server core (Phase 9.2), userspace.
 *
 * macOS-style, not an in-kernel GUI: each window has its own content surface; the
 * window server keeps the window list + z-order and composites surfaces back-to-
 * front over the desktop, drawing the chrome. The kernel only owns framebuffer +
 * input + IPC.
 *
 *     app -> (IPC) -> windowserver -> compositor -> framebuffer
 *
 * The wm_state_* core below is pure (no syscalls), so it is driven both by the
 * real `windowserver` process and by the host PNG renderer. Surface pixel buffers
 * are supplied by the caller (windowserver mallocs them; the host test too), so
 * this file needs no allocator and stays portable.
 */
#pragma once
#include "gfx.h"

#define WM_TITLEBAR_H  28    /* base height (at 100% UI scale); see wm_titlebar_h */
#define WM_MENUBAR_H   28    /* must match desktop.c MENUBAR_H (drag y-clamp) */
#define WM_MAX_WINDOWS 16
#define WM_MAX_UI_SCALE 200  /* the largest UI scale; present buffers are sized for
                              * this so a live scale change never needs a realloc */

/* Bounding box of the arrow cursor glyph (see cursor_glyph[] in wm.c). Used by
 * the windowserver to damage only the pixels the pointer covers. */
#define WM_CURSOR_W    12
#define WM_CURSOR_H    18

/* Color-key used for 1-bit transparency on borderless windows (e.g. the Dock's
 * rounded panel): content pixels equal to this are not blitted, so the desktop
 * shows through the panel's corners. Pick an unlikely magenta. */
#define WM_COLOR_KEY   0xFF00FFu

/* A window = an app-owned content surface + on-screen placement + z-order. */
typedef struct {
    int            id;
    int            x, y;        /* top-left of the window (title bar included) */
    int            z;           /* higher = closer to the front */
    int            visible;
    int            owner;       /* pid of the app that owns the window (for input) */
    int            decorated;   /* 1 = title bar + shadow chrome; 0 = borderless (Dock) */
    int            resizable;   /* 1 = the app handles WM_RESIZE (maximize works)  */
    int            shaded;      /* 1 = window-shaded (collapsed to its title bar)   */
    int            maximized;   /* 1 = filling the screen (saved geometry in s*)    */
    int            sx, sy, sw, sh;  /* geometry to restore from maximize           */
    int            dirty;       /* 1 = the cached presentation surface needs a rebuild */
    int            shm_id;      /* shared-surface id (server owns it), or -1 */
    const char    *title;
    gfx_surface_t *content;     /* the app's content surface (w x h, packed) */
    gfx_surface_t *present;     /* cached composed window (chrome+content), or NULL */
} window_t;

/* ---- compositor primitives ---- */

void wm_draw_window(gfx_surface_t *screen, const window_t *win);
void wm_composite(gfx_surface_t *screen, window_t *windows[], int n);

/* ---- UI scale ----
 * The scale percent lives in desktop.c (desktop_scale()); these report the
 * window chrome metrics at that scale so the server's footprint/allocation math
 * matches what wm.c draws. */
int  wm_titlebar_h(void);    /* WM_TITLEBAR_H scaled by the current UI scale */
/* Allocation footprint (in *fw,*fh) of a window's presentation surface for a
 * `content_w` x `content_h` content area, sized for the LARGEST UI scale so the
 * buffer is never reallocated when the scale changes. wm_refresh_surfaces draws
 * into it at the current scale, which is always within these bounds. */
void wm_present_footprint(int content_w, int content_h, int *fw, int *fh);

/* ---- window-server core (window table + z-order + drawing) ---- */

typedef struct {
    window_t      win[WM_MAX_WINDOWS];
    gfx_surface_t surf[WM_MAX_WINDOWS];
    gfx_surface_t psurf[WM_MAX_WINDOWS];    /* per-window cached presentation surfaces */
    char          titles[WM_MAX_WINDOWS][48];
    int           used[WM_MAX_WINDOWS];
    int           count, next_id, next_z;
    int           cursor_x, cursor_y;   /* pointer position (screen pixels)  */
    int           cursor_on;            /* draw the cursor on present?        */
} wm_state_t;

void wm_state_init(wm_state_t *st);
/* Register a window owned by `owner` (pid); `pixels` is a caller-owned w*h*4
 * content buffer. `decorated` = 1 for a normal window (title bar + shadow), 0
 * for a borderless window (the Dock draws its own chrome). `resizable` = 1 if the
 * app handles WM_RESIZE (so it can be maximized). Returns the id. */
int  wm_create(wm_state_t *st, int x, int y, int w, int h, const char *title,
               void *pixels, int owner, int decorated, int resizable);
/* 1 if window `id` has chrome (title bar/shadow); 0 if borderless / unknown. */
int  wm_is_decorated(wm_state_t *st, int id);
/* Top-left of window `id`'s *content* on screen (chrome accounted for). Returns
 * 1 and fills *ox,*oy, or 0 if unknown — used to map a pointer to app-local. */
int  wm_content_origin(wm_state_t *st, int id, int *ox, int *oy);
/* Force window `id` to the very front and keep it there (the Dock floats above
 * ordinary windows; it is excluded from keyboard focus, see wm_focus_owner). */
void wm_set_top(wm_state_t *st, int id);
/* Owner pid of the focused (top-most visible) window, or -1 if none. */
int  wm_focus_owner(wm_state_t *st);
/* Id of the top-most visible window whose frame (title bar + content) contains
 * (x, y), or -1 if the click landed on the desktop. */
int  wm_window_at(wm_state_t *st, int x, int y);
/* Is (x, y) inside window `id`'s title bar? (for click-to-focus / dragging) */
int  wm_in_titlebar(wm_state_t *st, int id, int x, int y);
/* Is (x, y) on window `id`'s close (red) / minimize (yellow) / maximize (green)
 * traffic-light button? */
int  wm_in_close_button(wm_state_t *st, int id, int x, int y);
int  wm_in_min_button(wm_state_t *st, int id, int x, int y);
int  wm_in_max_button(wm_state_t *st, int id, int x, int y);
/* Toggle window-shade (collapse to/expand from the title bar). Returns the new
 * shaded state, or -1 if `id` is unknown. */
int  wm_toggle_shade(wm_state_t *st, int id);
/* Toggle maximize for a *resizable* window. On success returns 1 and writes the
 * new content size to *w,*h (the server reallocs the surface to it and sends the
 * app WM_RESIZE); returns 0 if the window is unknown or not resizable. */
int  wm_toggle_max(wm_state_t *st, int id, int screen_w, int screen_h, int *w, int *h);
/* Replace window `id`'s content surface (after the server reallocs it). */
int  wm_set_content(wm_state_t *st, int id, void *pixels, int w, int h);
/* Clear the maximized flag without moving (e.g. when the window is dragged). */
void wm_clear_maximized(wm_state_t *st, int id);
/* Top-left of window `id` (title bar included); for computing a drag offset. */
int  wm_window_x(wm_state_t *st, int id);
int  wm_window_y(wm_state_t *st, int id);
/* Owner pid of window `id`, or -1 (so the server can notify it on close). */
int  wm_owner_of(wm_state_t *st, int id);
/* The top-most window owned by `owner` (pid), or -1; lets the server map an
 * app's WM_PRESENT back to the screen rectangle it needs to refresh. */
int  wm_window_of_owner(wm_state_t *st, int owner);
/* The content pixel buffer of window `id` (the one the windowserver malloc'd),
 * or NULL; the server frees it on destroy so closing a window leaks nothing. */
void *wm_content_ptr(wm_state_t *st, int id);

/* Shared-surface id of window `id` (-1 if its content is an ordinary malloc'd
 * buffer); set it after creating a WM_F_SHM window. The server uses it to free the
 * shared object (shm_destroy) instead of free() on destroy. */
int  wm_shm_id(wm_state_t *st, int id);
void wm_set_shm(wm_state_t *st, int id, int shm_id);

/* ---- per-window surface caching ----
 * Each decorated window's fully-composed pixels (shadow + chrome + content) are
 * cached in a server-owned presentation surface, so a drag/move just *blits* it
 * rather than re-rendering the chrome every frame. The surface is rebuilt only
 * when the window's content/geometry changes (the `dirty` flag). */
/* Attach a presentation buffer of footprint `fw`x`fh` to window `id` (server
 * owns `pixels`); marks it dirty. `pixels` NULL falls back to immediate drawing. */
void  wm_set_present(wm_state_t *st, int id, void *pixels, int fw, int fh);
/* The presentation pixel buffer of window `id`, or NULL (for the server to free). */
void *wm_present_ptr(wm_state_t *st, int id);
/* Mark window `id`'s presentation surface stale (its content/state changed). */
void  wm_mark_dirty(wm_state_t *st, int id);
/* Mark every live window's surface stale — used after a UI-scale change, which
 * alters the title-bar height (and thus every window's composed pixels). */
void  wm_mark_all_dirty(wm_state_t *st);
/* Rebuild the cached presentation surface of every dirty decorated window. Cheap
 * when nothing is dirty; called by the server once per frame before compositing. */
void  wm_refresh_surfaces(wm_state_t *st);
/* Number of live windows (for leak/limit diagnostics). */
int  wm_window_count(wm_state_t *st);
/* First used window id whose id != `except` (or -1). Lets the server iterate to
 * close every window but the Dock. */
int  wm_first_window_except(wm_state_t *st, int except);
/* Fill out[] (up to `cap`) with every live window id; returns the count. Lets the
 * server broadcast (e.g. a UI-scale change) to each window's owner. */
int  wm_list_windows(wm_state_t *st, int *out, int cap);
/* On-screen bounding box of window `id` including its drop shadow. Returns 1 and
 * fills *bx..*bh, or 0 if `id` is unknown. The windowserver uses this as the
 * damage rectangle so a redraw only touches that window's pixels. */
int  wm_window_bounds(wm_state_t *st, int id, int *bx, int *by, int *bw, int *bh);
/* Raise window `id` to the front (highest z) so it gains focus. */
void wm_raise(wm_state_t *st, int id);
void wm_draw_rect(wm_state_t *st, int id, int x, int y, int w, int h, uint32_t color);
void wm_draw_round_rect(wm_state_t *st, int id, int x, int y, int w, int h, int r, uint32_t color);
void wm_draw_text(wm_state_t *st, int id, int x, int y, const char *s, uint32_t color);
void wm_clear(wm_state_t *st, int id, uint32_t color);
void wm_move(wm_state_t *st, int id, int x, int y);
/* Like wm_move, but clamp so a graspable strip always stays on-screen and the
 * title bar never slides under the menu bar. */
void wm_move_clamped(wm_state_t *st, int id, int x, int y, int screen_w, int screen_h);
void wm_destroy(wm_state_t *st, int id);
/* Paint the desktop, then all visible windows by z-order, onto `screen` — the
 * scene *without* the pointer. The windowserver composites into an off-screen
 * back buffer with this, then blits only the changed rectangles to the
 * framebuffer (and overlays the cursor itself). */
void wm_compose(wm_state_t *st, gfx_surface_t *screen);
/* Composite only the windows (no desktop, no cursor) onto an already-prepared
 * surface — for callers that supply a cached background instead of redrawing it. */
void wm_composite_windows(wm_state_t *st, gfx_surface_t *screen);
/* Draw the arrow cursor at (px, py) on top of `screen`. */
void wm_draw_cursor(gfx_surface_t *screen, int px, int py);
/* Convenience: wm_compose + the cursor on top. Used by the host PNG renderer
 * (a single full frame); the live server uses wm_compose + damage blits. */
void wm_present(wm_state_t *st, gfx_surface_t *screen);

/* ---- window IPC protocol (spoken by the windowserver daemon) ---- */

#define WM_SERVICE "wm"

/* WM_CREATE flags (req.flags). */
#define WM_F_DOCK       1   /* borderless, pinned bottom-center, always on top,
                             * excluded from keyboard focus, receives WM_POINTER */
#define WM_F_RESIZABLE  2   /* the app handles WM_RESIZE, so it can be maximized  */
#define WM_F_SHM        4   /* content is a shared-memory surface: the server
                             * allocates it, the client maps the id from the reply
                             * and renders into it directly (no WM_DRAW_* IPC)     */

enum {
    WM_CREATE = 1,   /* app -> server: new window (w,h,title,flags); reply = id */
    WM_DESTROY,      /* app -> server: destroy a window                        */
    WM_MOVE,         /* app -> server: move a window to (x,y)                  */
    WM_DRAW_RECT,    /* app -> server: fill a rect in the window's surface     */
    WM_DRAW_TEXT,    /* app -> server: draw text in the window's surface       */
    WM_PRESENT,      /* app -> server: recomposite to the screen               */
    WM_KEY,          /* kbd helper -> server, then server -> focused app: a key
                        (the character is in req.x)                            */
    WM_MOUSE,        /* mouse helper -> server: a pointer event
                        (req.x = dx, req.y = dy, req.w = button bitmask)       */
    WM_DRAW_ROUND_RECT, /* app -> server: rounded rect (req.flags = radius)    */
    WM_POINTER,      /* server -> app: pointer over the app's window
                        (req.x,req.y = content-local; req.w = button bitmask)  */
    WM_STAT,         /* app -> server: log live-window count + heap top (debug) */
    WM_RESIZE,       /* server -> app: your content is now req.w x req.h; redraw */
    WM_RELOAD_SETTINGS, /* app -> server: re-read /disk/settings.cfg (theme)     */
    WM_TICK,         /* render ticker -> server: a frame is due (render if dirty) */
    WM_SCALE,        /* server -> app: the UI scale changed; re-query ui_scale()
                        and re-lay-out + repaint your content                    */
    WM_CLIPBOARD_SET,/* app -> server: store req.str as the clipboard text       */
    WM_CLIPBOARD_GET,/* app -> server: request the clipboard; server replies with
                        the same op and the text in req.str                      */
};

typedef struct {
    int      op;
    int      win;
    int      x, y, w, h;
    uint32_t color;
    int      flags;        /* WM_CREATE: window flags; DRAW_ROUND_RECT: radius */
    char     str[48];      /* window title (CREATE) or text (DRAW_TEXT) */
} wm_req_t;

typedef struct {
    int status;            /* 0 = ok, <0 = error */
    int win;               /* assigned window id (on WM_CREATE) */
    int shm;               /* shared-surface id to map (WM_F_SHM), else -1 */
} wm_rep_t;
