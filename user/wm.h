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

#define WM_TITLEBAR_H  28
#define WM_MAX_WINDOWS 16

/* A window = an app-owned content surface + on-screen placement + z-order. */
typedef struct {
    int            id;
    int            x, y;        /* top-left of the window (title bar included) */
    int            z;           /* higher = closer to the front */
    int            visible;
    int            owner;       /* pid of the app that owns the window (for input) */
    const char    *title;
    gfx_surface_t *content;     /* the app's content surface (w x h, packed) */
} window_t;

/* ---- compositor primitives ---- */

void wm_draw_window(gfx_surface_t *screen, const window_t *win);
void wm_composite(gfx_surface_t *screen, window_t *windows[], int n);

/* ---- window-server core (window table + z-order + drawing) ---- */

typedef struct {
    window_t      win[WM_MAX_WINDOWS];
    gfx_surface_t surf[WM_MAX_WINDOWS];
    char          titles[WM_MAX_WINDOWS][48];
    int           used[WM_MAX_WINDOWS];
    int           count, next_id, next_z;
} wm_state_t;

void wm_state_init(wm_state_t *st);
/* Register a window owned by `owner` (pid); `pixels` is a caller-owned w*h*4
 * content buffer. Returns the window id. */
int  wm_create(wm_state_t *st, int x, int y, int w, int h, const char *title,
               void *pixels, int owner);
/* Owner pid of the focused (top-most visible) window, or -1 if none. */
int  wm_focus_owner(wm_state_t *st);
void wm_draw_rect(wm_state_t *st, int id, int x, int y, int w, int h, uint32_t color);
void wm_draw_text(wm_state_t *st, int id, int x, int y, const char *s, uint32_t color);
void wm_clear(wm_state_t *st, int id, uint32_t color);
void wm_move(wm_state_t *st, int id, int x, int y);
void wm_destroy(wm_state_t *st, int id);
/* Paint the desktop, then all visible windows by z-order, onto `screen`. */
void wm_present(wm_state_t *st, gfx_surface_t *screen);

/* ---- window IPC protocol (spoken by the windowserver daemon) ---- */

#define WM_SERVICE "wm"

enum {
    WM_CREATE = 1,   /* app -> server: new window (w,h,title); reply = id      */
    WM_DESTROY,      /* app -> server: destroy a window                        */
    WM_MOVE,         /* app -> server: move a window to (x,y)                  */
    WM_DRAW_RECT,    /* app -> server: fill a rect in the window's surface     */
    WM_DRAW_TEXT,    /* app -> server: draw text in the window's surface       */
    WM_PRESENT,      /* app -> server: recomposite to the screen               */
    WM_KEY,          /* kbd helper -> server, then server -> focused app: a key
                        (the character is in req.x)                            */
};

typedef struct {
    int      op;
    int      win;
    int      x, y, w, h;
    uint32_t color;
    char     str[48];      /* window title (CREATE) or text (DRAW_TEXT) */
} wm_req_t;

typedef struct {
    int status;            /* 0 = ok, <0 = error */
    int win;               /* assigned window id (on WM_CREATE) */
} wm_rep_t;
