# AuroraOS Input & Pointer — Phase 9.3+ (design)

This is the **architecture** for mouse/cursor/focus/drag, prepared ahead of
implementation. Per the agreed rule, the PS/2 mouse driver and its IRQ routing
are **not** written until the live GUI loop (9.2) is confirmed on a real QEMU
screen — building hardware/IRQ code blind would be wasted if the framebuffer
behaves differently than assumed. This doc fixes the interfaces so the
implementation is turnkey once 9.2 is green.

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

## Kernel side (smallest possible, written only after 9.2 is green)

- **PS/2 mouse driver:** enable the aux device on the 8042 controller, handle
  **IRQ12**, assemble the 3-byte packet (flags, dx, dy). Expose events to
  userspace the same way the keyboard is exposed — the simplest fit is a tiny
  blocking read source the windowserver's reader child consumes (e.g. a
  `mouse`-flavoured read, analogous to `read(0)` for the keyboard). No new policy
  in the kernel; it only delivers raw packets.
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

## Windowserver side (all userspace, all PNG-testable before going live)

- **9.3 — Cursor.** Keep a cursor position `(cx, cy)`; each `WM_MOUSE` adds
  `dx,dy` clamped to the screen. The compositor draws a small arrow at `(cx,cy)`
  **last** (on top of everything) in every full recomposite. Movement triggers a
  recomposite.
- **9.4 — Click-to-focus.** On left-button press, hit-test the windows
  top-to-bottom for the one containing `(cx,cy)`; raise it (give it the highest
  `z`) and make it the focused window (so `WM_KEY` routes to it). `wm.c` already
  has `wm_focus_owner`; add `wm_window_at(x,y)` and `wm_raise(id)`.
- **9.5 — Window dragging.** If the press lands in a window's title bar, enter a
  drag: subsequent motion sets that window's `(x, y)` (via the existing
  `wm_move`) and recomposites; button release ends the drag. This is the headline
  milestone — grab a window by its title bar and move it.
- **9.6 — Dock as its own process.** Split the Dock out of `desktop.c` into a
  `dock` app that owns a strip window and launches apps via IPC.
- **9.7 — Launcher / Finder** (`Aurora Files`) as real windowed apps over the VFS
  (FS write already exists).

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
9.2 (confirm live)  →  9.3 cursor  →  9.4 click-to-focus  →  9.5 drag
                    →  9.6 Dock process  →  9.7 Launcher/Finder
later: client-side surfaces · shared memory · animations · networking
```
