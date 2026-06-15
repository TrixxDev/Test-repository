/* AuroraOS window model + compositor (Phase 9.2), userspace.
 *
 * The design follows macOS, not an in-kernel GUI: each app renders into its own
 * off-screen *surface*; the window server composites the surfaces (back-to-front
 * by z-order) onto the screen, drawing the chrome (title bar, traffic lights,
 * shadow) around each. The kernel only owns framebuffer + input + IPC.
 *
 *     app -> surface -> window server -> compositor -> framebuffer
 *
 * This header is portable (host PNG renderer today; the windowserver daemon
 * tomorrow). The IPC protocol below is the contract that daemon will speak.
 */
#pragma once
#include "gfx.h"

#define WM_TITLEBAR_H 28
#define WM_MAX_WINDOWS 32

/* A window = an app-owned content surface + on-screen placement + z-order. */
typedef struct {
    int            id;
    int            x, y;        /* top-left of the window (title bar included) */
    int            z;           /* higher = closer to the front */
    int            visible;
    const char    *title;
    gfx_surface_t *content;     /* the app's content surface (w x h, packed) */
} window_t;

/* Draw one window's chrome + content onto `screen`. */
void wm_draw_window(gfx_surface_t *screen, const window_t *win);

/* Composite `windows` (back-to-front by z-order) onto `screen`, which is assumed
 * to already hold the desktop background. */
void wm_composite(gfx_surface_t *screen, window_t *windows[], int n);

/* ---- window IPC protocol (spoken by the future userspace windowserver) ---- */

#define WM_SERVICE "wm"

enum {
    WM_CREATE  = 1,   /* app: create a window of (w,h) with a title -> win id   */
    WM_DESTROY,       /* app: destroy a window                                  */
    WM_PRESENT,       /* app: its surface has new content; recomposite          */
    WM_MOVE,          /* app/server: move a window to (x,y)                     */
};

typedef struct {
    int  op;
    int  win;
    int  x, y, w, h;
    char title[48];
} wm_req_t;

typedef struct {
    int status;       /* 0 = ok, <0 = error */
    int win;          /* assigned window id (on WM_CREATE) */
} wm_rep_t;
