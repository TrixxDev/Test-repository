# AuroraOS Input & Pointer — Phase 9.3+

**Status: 9.3 (mouse + cursor + click-to-focus), 9.4/9.5 (window dragging +
close button) and 9.6 (the Dock as a separate process) are implemented and
verified live in QEMU (v0.9.9).** The PS/2 mouse driver + IRQ12, the cursor,
hit-testing, click-to-focus, title-bar dragging and the close button all work on
the real framebuffer; the windowserver also **forwards pointer events to the app
under the cursor** (`WM_POINTER`), which the Dock uses for hover + click-to-launch.
Regenerate the proofs with `make demo-focus` (→ `aurora_live_focus.png`: the back
window is clicked, raised, and typed into), `make demo-drag` (→ `aurora_live_drag.png`:
the front Terminal is grabbed by its title bar and moved), `make demo-close`
(→ `aurora_live_close.png`: its red button is clicked and the window disappears)
and `make demo-dock` (→ `aurora_live_dock.png`: a Dock icon is clicked and a new
Terminal launches). `tools/verify_drag.py` pixel-asserts drag + close. This doc is
the design + the as-built reference.

## Data flow (mirrors the keyboard pipeline)

```
PS/2 mouse  ──IRQ12──►  kernel PS/2 driver  ──►  input source (read-like)
                                                     │
        windowserver "input reader" child ──read──►──┘
                                                     │ WM_MOUSE / WM_KEY (IPC)
                                              windowserver event loop
                                                     │
                                cursor + hit-test + focus + drag
                                                     │ full recomposite
                                                  framebuffer
```

The keyboard already works this way (a forked reader child does `read(0)` and
forwards `WM_KEY`). The mouse adds a second reader child that forwards
`WM_MOUSE`. The windowserver event loop stays single-source (one mailbox).

## Kernel side (as built — `drivers/mouse.c`)

- **PS/2 mouse driver:** `mouse_install()` enables the aux device on the 8042
  (`0xA8`), turns on IRQ12 + the aux clock in the controller config byte, and
  sets the mouse to defaults + data reporting (`0xF6`, `0xF4`). The **IRQ12**
  handler (vector 44, already in the IDT) assembles the 3-byte packet
  (flags, dx, dy), sign-extends dx/dy, and pushes raw PS/2 deltas into a ring
  buffer. `mouse_get()` maps them to screen coords (`-dx`, `dy`; dy > 0 = down).
- Userspace reads one event via the **`SYS_MOUSE` (28)** syscall
  (`mouse_read(int out[3])` → `{dx, dy, buttons}`, blocking). The windowserver
  adds deltas directly to `(cursor_x, cursor_y)`.
- That is the **entire** kernel addition. Cursor, focus, drag and z-order changes
  are all userspace, in the windowserver.

## Wire format (userspace protocol, extends wm.h)

```c
enum { /* ...existing WM_* ... */
    WM_MOUSE,        /* input reader -> server: a pointer event */
};

typedef struct {            /* carried in the existing wm_req_t-style message */
    int op;                 /* WM_MOUSE */
    int dx, dy;             /* relative motion (mouse units)        */
    int buttons;            /* bit0 = left, bit1 = right, bit2 = mid */
} wm_mouse_t;
```

(One mailbox still carries `WM_KEY`, `WM_MOUSE` and the app draw requests; the
server branches on `op`.)

## Windowserver side (all userspace)

- **9.3 — Cursor. DONE.** `wm_state_t` keeps `(cursor_x, cursor_y)` + `cursor_on`;
  each `WM_MOUSE` adds `dx,dy` clamped to the screen. `wm_present` draws a small
  arrow at the cursor **last** (on top of everything) in every full recomposite.
  Movement triggers a recomposite. (The host PNG renderer leaves `cursor_on = 0`,
  so its output is unchanged.)
- **9.3 — Click-to-focus. DONE.** On a left-button press edge, `wm_window_at(x,y)`
  hit-tests the windows top-to-bottom; `wm_raise(id)` gives the hit window the
  highest `z`, which makes it the focused window (so `WM_KEY` routes to it via the
  existing `wm_focus_owner`). Verified: clicking the back Terminal raises it and
  subsequent typing lands in it.
- **9.4/9.5 — Window dragging. DONE.** The windowserver's `WM_MOUSE` handler runs a
  small drag state machine (`drag_state_t { active, window_id, offset_x, offset_y }`
  in `user/wserver.c`):
  - **press** inside a title bar (`wm_in_titlebar`) records the window and the
    cursor-to-origin offset (`offset = cursor - wm_window_x/y`), after the usual
    `wm_raise` for click-to-focus;
  - **motion** while the button is held re-places the window via `wm_move_clamped`
    (keeps `cursor - offset` under the grabbed point), clamped so a 40px graspable
    strip always stays on-screen and the title bar never slides above `WM_MENUBAR_H`;
  - **release** clears `drag.active`.
- **9.5 — Close button. DONE.** A **press** on the red title-bar light
  (`wm_in_close_button`, the left traffic light at `(x+16, y+14)`, drawn with a
  small dark "×") destroys the window (`wm_destroy`) and sends its `owner` a
  `WM_DESTROY` message; the app (e.g. `user/term.c`) treats that as "quit" and
  exits, so init reaps it. Drawn/handled entirely in userspace.
- **9.6 — Dock as its own process. DONE.** The Dock (`user/dock.c`) is no longer
  drawn by `desktop.c`; it is an ordinary userspace app and the first standalone
  GUI client of the window server. It asks for a **borderless** window with the
  `WM_F_DOCK` flag, which the server pins to the bottom-center, keeps always on top
  (a fixed high z), and excludes from keyboard focus (`wm_focus_owner` skips
  non-decorated windows). It draws a rounded panel of icons using a new
  `WM_DRAW_ROUND_RECT` request, with the panel's corners left at `WM_COLOR_KEY` so
  the desktop shows through (1-bit transparency in the compositor's `blit_keyed`).
  To make it interactive, the server **forwards pointer events** to the window
  under the cursor as `WM_POINTER` (content-local `x,y` + button mask), unless a
  drag is in progress; the Dock highlights the hovered icon and, on a left-click,
  launches the app (`fork` + double-`fork` + `exec`, so the new app reparents to
  init for reaping). Proof: `make demo-dock`.
- **9.7 — Launcher / Finder** (`Aurora Files`) as real windowed apps over the VFS
  (FS write already exists). **NEXT.** It will reuse the same `WM_POINTER` plumbing
  the Dock introduced (click a file row → open/launch).

Note: the cursor/hit-test/focus/drag logic is pure and can be exercised with the
off-screen renderer (drive `wm_*` + synthetic mouse events) *if* useful — but the
real value is the live drag, so we confirm it in QEMU rather than chasing more
PNGs.

## Deliberately deferred (after the desktop feels real)

Client-side **shared-memory surfaces**, animations, and the **network stack**
(virtio-net/TCP) all wait until there are several working windowed apps. The
current `app → IPC → windowserver → framebuffer` path is sufficient for the first
windows; macOS-likeness now comes from windows + focus + cursor + dragging +
Dock + menus, not from render throughput.

## Order

```
9.2 (live ✅) → 9.3 cursor + click-to-focus (✅) → 9.4/9.5 window dragging + close (✅)
             → 9.6 Dock process (✅) → 9.7 Launcher/Finder (next)
later: client-side surfaces · shared memory · animations · networking
```
