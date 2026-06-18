# AuroraOS Input & Pointer — Phase 9.3+

**Status: 9.3 (mouse + cursor + click-to-focus), 9.4/9.5 (window dragging +
close button), 9.6 (the Dock as a separate process) and 9.7 (the Finder,
`Aurora Files`) are implemented and verified live in QEMU (v0.9.10).** The PS/2
mouse driver + IRQ12, the cursor, hit-testing, click-to-focus, title-bar dragging
and the close button all work on the real framebuffer; the windowserver also
**forwards pointer events to the app under the cursor** (`WM_POINTER`), which the
Dock uses for hover + click-to-launch and the Finder uses for row selection +
open. Regenerate the proofs with `make demo-focus` (→ `aurora_live_focus.png`: the
back window is clicked, raised, and typed into), `make demo-drag` (→ `aurora_live_drag.png`:
the front Terminal is grabbed by its title bar and moved), `make demo-close`
(→ `aurora_live_close.png`: its red button is clicked and the window disappears),
`make demo-dock` (→ `aurora_live_dock.png`: a Dock icon is clicked and a new
Terminal launches) and `make demo-files` (→ `aurora_live_files.png`: the Finder
opens from the Dock, lists `/disk`, and launches `TERM.ELF` on double-click).
`tools/verify_drag.py` pixel-asserts drag + close. This doc is the design + the
as-built reference.

## Data flow (mirrors the keyboard pipeline)

```
PS/2 mouse  ──IRQ12──►  kernel PS/2 driver  ──►  input source (read-like)
                                                     │
        windowserver "input reader" child ──read──►──┘
                                                     │ WM_MOUSE / WM_KEY (IPC)
                                              windowserver event loop
                                                     │
                                cursor + hit-test + focus + drag
                                                     │ update state + record damage
                                  render ticker ──WM_TICK──► render_frame (fixed cadence)
                                                     │ damage compose + flush
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
  (`mouse_read(int out[4])` → `{x, y, buttons, absolute}`, blocking). For a
  relative event the windowserver adds `x/y` to `(cursor_x, cursor_y)`; for an
  absolute event it scales them onto the current mode (see below).
- That is almost the **entire** kernel addition. Cursor, focus, drag and z-order
  changes are all userspace, in the windowserver.

### Absolute pointer (`abs` cmdline → QEMU/VMware "vmmouse")

By default the mouse is **relative** (PS/2 deltas), which is correct on real
hardware but means the guest cursor drifts from the host pointer — and the drift
changes with resolution. When the kernel boots with **`abs`** on the command line
(the `make run-vbe`/`gui` paths and `boot/grub.cfg` pass it), `mouse_install()`
also enables the **vmmouse backdoor** (I/O port `0x5658`): it probes via the
VMware version call, sends `READID`, drains the version handshake word (otherwise
every 4-word event read is off by one), then requests absolute mode. The device
has no IRQ of its own — QEMU still raises **IRQ12** with a throw-away PS/2 packet,
so the same packet state-machine fires; on a complete packet the handler reads the
absolute `(buttons, x, y, z)` out of the backdoor queue instead of using the PS/2
deltas. `x/y` arrive in `0..0xFFFF`; the windowserver scales them to the live mode
(`cursor_x = x * (screen.width-1) / 0xFFFF`), so **the guest cursor sits exactly
on the host pointer at any resolution**. If the backdoor is absent (real hardware)
or reports an error, it silently falls back to PS/2 relative. The headless test
harness keeps the relative path (no `abs`), so scripted clicks are unaffected;
`tools/screendump.py --append abs --mouse "abs:X,Y"` exercises the absolute path
(verified centering + corners at 1024×768 and 800×600).

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
- **10.1 — Minimize + Maximize. DONE (v1.1.0).** The yellow and green title-bar
  lights are now live. **Yellow = window-shade**: `wm_toggle_shade` collapses the
  window to its title bar (content hidden, hit area + bounds shrink to the bar);
  a second click expands it. **Green = maximize/restore**: only for windows that
  opted in with `WM_F_RESIZABLE`. `wm_toggle_max` saves the geometry and computes
  the full-screen content size; the server **reallocs the content surface**
  (it owns the buffer) and sends the app a **`WM_RESIZE {w,h}`** message; the app
  (Terminal/Finder/Viewer) recomputes its layout and redraws. Restore reverses it.
  Proof: `make demo-max` / `make demo-min`.
- **10.2 — Aurora system menu. DONE (v1.1.1).** The menu bar's "Aurora" title is
  hit-tested by the windowserver: a press toggles a dropdown (drawn into the back
  buffer as chrome, above all windows). A press on an item runs it and closes the
  menu; a press elsewhere just closes it; hovering highlights items. Actions:
  **About** → spawn the Viewer on `ABOUT.TXT`; **Settings** → spawn the settings
  app (both via a windowserver double-`fork`+`exec`); **Close All Windows** →
  destroy every window but the Dock; **Shut Down** → paint a final screen + the
  `halt` syscall. Lives in the windowserver so it survives a dead Dock.
  Proof: `make demo-menu`.
- **10.3 — Settings. DONE (v1.1.2).** The Settings app (Aurora menu → Settings)
  takes pointer clicks (`WM_POINTER`) on its Desktop pane to choose a wallpaper +
  accent, writes them to `/disk/settings.cfg` (just the VFS), and sends the
  windowserver `WM_RELOAD_SETTINGS`; the server re-reads the file (also at boot)
  and re-themes the desktop. A System pane shows `sysinfo`. Proof: `make
  demo-settings`.
- **10.4 — Clipboard. DONE.** Last-writer-wins text clipboard backed by a single
  **shared-memory buffer** (`WM_CLIP_SIZE` = 4 KiB) the server creates at startup and
  hands to each app in the `WM_CREATE` reply (`rep.clip`); the app maps it once and
  reads/writes it directly (`user/libc/clip.c`), so copy/paste is not limited to the
  IPC message size. Apps copy with `WM_CLIPBOARD_SET` (the length in `req.x`; the text
  is already in the shared buffer) and paste with `WM_CLIPBOARD_GET` (the server
  replies with the length, then the app reads the shared buffer). The keyboard
  driver now tracks **Control** (`drivers/keyboard.c`): `Ctrl`+letter yields control
  codes 1–26, so **Ctrl+C / Ctrl+V** flow through the normal `WM_KEY` pipeline.
  The Terminal copies its input line and pastes into it; the Finder copies the
  selected file name; the Viewer lets you **click a line to select it** (it
  highlights) and copies the selected (or top) line. Cross-app verified
  (Finder → Ctrl+C → Terminal → Ctrl+V).
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
- **9.7 — Finder (`Aurora Files`). DONE.** `user/files.c` lists a directory via the
  new `readdir` syscall (the VFS through ordinary syscalls, like the shell) and
  reuses the Dock's `WM_POINTER` plumbing: a click selects a row, a click on the
  selected row opens it (enter a directory / `..` up / exec an `.ELF` / hand other
  files to the Viewer). Verified with `make demo-files`. **9.8 — Text Viewer** is
  next (open `POEM.TXT` from the Finder).

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
             → 9.6 Dock process (✅) → 9.7 Finder (✅) → 9.8 Text Viewer (next)
later: client-side surfaces · shared memory · animations · networking
```
