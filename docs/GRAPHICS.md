# AuroraOS Graphics — Phase 9.0 / 9.1 (first pixels)

The goal for AuroraOS is a macOS-like desktop, so the visual stack starts early
and is built with the right layering from day one — applications will never draw
to the framebuffer directly:

```
app → window server → compositor → framebuffer
```

Phases 9.0 (framebuffer) and a minimal 9.1 (2D library) are in; the window
server / compositor (9.2) are next. What exists today renders a **static**
desktop straight onto the framebuffer.

## 9.0 — Framebuffer (`drivers/fb.c`)

The Multiboot header (`arch/i386/boot.S`) requests a 1024×768×32 linear video
mode. `fb_init()` (`drivers/fb.c`) brings up a framebuffer two ways and wraps it
in a `gfx_surface_t`; if neither is available the kernel stays in VGA text mode
(fully gated, so the text boot is never affected):

1. **Loader-provided (preferred).** If the loader honors the Multiboot video
   request, `multiboot_info_t` carries `framebuffer_addr/pitch/width/height/bpp`
   and we use it directly. GRUB does this.
2. **Bochs/std-VGA VBE fallback.** Bare `qemu -kernel` may ignore the request, so
   on the opt-in cmdline flag `vbe` we set the mode ourselves: program the Bochs
   DISPI registers (ports `0x01CE/0x01CF`) for 1024×768×32 + LFB, and find the
   framebuffer address from the PCI display controller's BAR0 (config ports
   `0xCF8/0xCFC`). Gated on the cmdline so the default boot is untouched.

### Seeing it live in QEMU

```sh
make run-vbe     # easiest: QEMU only, no GRUB tools (Bochs-VBE fallback)
make gui         # one command: build + GRUB ISO + boot the desktop
```

`make gui` is the "real boot" path (build → `grub-mkrescue` ISO → QEMU with the
disk attached); it needs `grub-mkrescue` + `xorriso` + `mtools`. If you don't
have those, `make run-vbe` brings up the identical desktop with plain QEMU,
because the kernel sets the VBE mode itself. Equivalent manual command:

```sh
make iso && qemu-system-i386 -cdrom aurora.iso -m 1024 -vga std -serial stdio \
    -drive file=disk.img,format=raw,if=ide
```

## 9.1 — 2D library (`kernel/gfx.c`)

Pure, portable software rendering over a linear 32-bpp surface
(`gfx_surface_t { pixels, width, height, pitch, bpp }`), colors `0x00RRGGBB`:

- `gfx_clear`, `gfx_fill_rect`, `gfx_draw_rect`
- `gfx_fill_round_rect` (quarter-circle corners), `gfx_fill_circle`
- `gfx_fill_vgradient` (per-scanline channel interpolation)
- `gfx_blit` (copy an image rectangle)
- `gfx_draw_char` / `gfx_draw_text` over an **8×16 bitmap font**
  (`kernel/font8x16.h`, ASCII 32..126)

No alpha blending yet (that comes with the design system, 9.6). The same code
runs in the kernel and on the host.

### Font

`kernel/font8x16.h` is a 1-bpp 8×16 font generated once from a monospace TTF by
`tools/genfont.py` (committed, so the build has no font dependency). Text is
essential for debugging the GUI — menu labels, the clock and the Dock icon
letters in the desktop all use it.

## First desktop (`kernel/desktop.c`)

`desktop_render(surface)` paints:

- a blue→violet gradient **wallpaper** with a centered greeting,
- a light **menu bar**: logo accent, "Aurora" wordmark, menu items
  (File/Edit/View/Window/Help), a clock, and a hairline separator,
- a dark rounded **Dock** centered at the bottom with five rounded, lettered app
  icons.

`kmain` calls it once after boot (`fb_draw_desktop`). It is a static scene — the
"does it look like an OS?" milestone before the window server exists.

## Previewing without a display

Because the 2D code is portable, the desktop can be rendered off-screen and
saved as an image — no QEMU or monitor required:

```sh
make screenshot      # -> aurora_desktop.png
```

This compiles `kernel/gfx.c` + `kernel/desktop.c` via `tools/render_desktop.c`
into an off-screen buffer and converts it to PNG (`tools/ppm2png.py`). It is both
the project's reference screenshot and the way the rendering is verified in this
environment.

## Verifying 9.2 live (the gate) — PASSED ✅

Phase 9.2 is confirmed on a real (emulated) framebuffer. The four gate checks all
hold on a live QEMU boot:

1. ✅ the **Terminal** window appears over the desktop;
2. ✅ typing produces text in it (keyboard → windowserver → app → redraw);
3. ✅ **focus** works (the top-most window receives keys);
4. ✅ no artifacts from the full recomposite on each `PRESENT`.

Serial (`-serial stdio`) shows the expected markers:
`[fb] Bochs VBE 1024x768 x32 LFB=0x... pitch=4096`,
`[wm] ready (pid 4), framebuffer 1024x768 pitch 4096`, `[term] opened window 1`.

### How it was verified (and how to reproduce headlessly)

The framebuffer can be captured without a display: boot the real kernel with the
VBE path, drive the QEMU monitor to `screendump` the live framebuffer, and
convert the PPM to PNG. `tools/screendump.py` automates this and can inject
keystrokes first (to prove the keyboard pipeline end-to-end):

```sh
make live-shot     # -> aurora_live.png        (the live desktop + Terminal)
make verify-gui    # -> aurora_live_typed.png  (types "hello aurora" into it)
```

These are *real* framebuffer captures (not the host `render_*` previews), so they
are the on-screen evidence for the gate. Interactively, `make run-vbe`
(or `make gui` via GRUB) opens the same desktop in a QEMU window.

> **The bug that was hiding behind the gate.** `make run-vbe` originally looked
> like it "did nothing" (it stayed in text mode) and on some QEMU builds reset in
> a boot loop. Root cause: `pmm_init` reserved only the kernel image, not the
> Multiboot structures the loader leaves in RAM just above it (info struct, memory
> map, **command line**). The first frame allocations overwrote them, so the
> `vbe` command line was read back as garbage and the framebuffer never came up
> (and, depending on where a given QEMU places those structures, the corruption
> could fault even earlier). `pmm_init` now reserves the Multiboot info, mmap,
> command line and boot-loader name. See `arch/i386/pmm.c`.

If a screen is ever black/garbled on a different setup, send the serial log — the
usual suspects are the PCI LFB address, the pitch, or the VBE mode-set. Input
next steps (mouse/cursor/drag) live in [INPUT.md](INPUT.md).

## 9.2 — Window server (userspace process), PNG-verified core

A real daemon, `user/wserver.c` (registered as `wm`, like `logger`/`netd`) —
**not** in the kernel. The kernel only adds one primitive: `fb_map` maps the
active framebuffer into the windowserver's address space.

- **Surface model.** Each window has its own content surface (`gfx_surface_t`).
  Apps never touch the screen.
- **Window-server core** (`user/wm.c`, pure/portable): the window table, z-order,
  drawing into a window's surface (`wm_create/draw_rect/draw_text/move/destroy`)
  and `wm_present` (paint the desktop, then all windows back-to-front by z).
- **Window chrome** (`wm_draw_window`): rounded title bar, three traffic-light
  buttons, centered title, drop shadow, then the app's content blitted in.
- **Window IPC protocol** (`WM_CREATE/DESTROY/MOVE/DRAW_RECT/DRAW_TEXT/PRESENT`,
  `wm_req_t`/`wm_rep_t`): how apps talk to the server.
- **First app:** `user/term.c` (Terminal) — a separate process that looks up
  `wm`, creates a window and draws a static shell session into it. `init` starts
  the windowserver + Terminal.

The window-server core is exercised by the host renderer, which drives the very
same `wm_state` API the daemon does:

```sh
make screenshot-wm     # -> aurora_windows.png  (Terminal over Aurora Files)
```

### Event loop, frame consistency, input (9.2 stabilization)

The windowserver is a single-source **event loop** — one mailbox carries both app
requests and keys:

```
for (;;) { req = msgrecv(); switch (req.op) { CREATE / DRAW_* / MOVE / PRESENT / KEY } }
```

Two invariants, deliberately simple at this stage:

- **Frame consistency:** only the windowserver writes the framebuffer. The kernel
  no longer paints the desktop itself; the windowserver owns the screen.
- **Double-buffered, damage-driven compositing (v0.9.8):** the scene (desktop +
  windows, *without* the cursor) is composited into an off-screen **back buffer**
  in RAM via `wm_compose`, and only the **changed rectangles** are copied to the
  framebuffer (slow VRAM), with the cursor overlaid on top during the copy. So:
  - a plain pointer move never recomposites the scene — it just restores the few
    pixels under the old cursor (from the back buffer) and redraws the arrow at
    the new spot (≈ two 12×18 blits instead of a 3 MB full-screen repaint);
  - a window draw (`PRESENT`), move, raise, drag or close recomposites the back
    buffer once and pushes only that window's footprint — for a drag, the union
    of the old and new footprints — to the framebuffer.

  `wm_window_bounds` gives a window's on-screen footprint (content + title bar +
  drop shadow) as the damage rectangle; `wm_window_of_owner` maps an app's
  `PRESENT` back to the rectangle it needs refreshed. The damage-driven output is
  **pixel-identical** to a full recomposite (verified: 0 differing pixels against
  the old full-repaint frame) — only the amount of VRAM touched per event drops.
  `wm_present` (full scene + cursor in one pass) is kept for the host PNG renderer.

- **Cached background + clipped recompose (v1.1.x perf pass):** the static
  background — the wallpaper gradient + menu bar — is rendered **once** into a
  separate cache surface (`rebuild_bg`) and rebuilt only when the theme changes
  (startup, `WM_RELOAD_SETTINGS`). `compose()` then *blits* the cache into the
  back buffer instead of recomputing the per-pixel gradient on every event, which
  used to dominate every drag frame. During a drag, `compose_dmg(rect)` refreshes
  only the **damage rectangle** of the background before redrawing the windows, so
  a drag step costs ≈ O(damage) rather than O(screen). Windows are still redrawn
  in full (idempotent outside the rect, since the scene there is unchanged), and
  only the damage rect is flushed, so the result stays **pixel-identical** to the
  full recomposite (`verify_drag` still passes). `wm_composite_windows` composites
  just the windows onto a caller-supplied background; `wm_compose` (desktop +
  windows) is kept for the host PNG renderer.

- **Mouse-event coalescing / FPS cap (v1.1.x perf pass):** the PS/2 mouse can
  emit ~200 events/s, but the compositor only needs to paint as fast as it can.
  When a `WM_MOUSE` arrives the event loop drains the mailbox **non-blockingly**
  (`msgrecv_nb`, backed by a new `MSG_NOWAIT` flag OR'd into `msgrecv`'s length
  argument) and **coalesces** consecutive same-button motion into one event by
  summing the deltas, then does a single recomposite. This caps the compose/flush
  rate at the server's render throughput instead of the packet rate — no wall-clock
  frame timer needed, since draining the backlog each iteration self-limits the
  work. Button **edges** (press/release) and non-mouse messages break the run, so
  clicks are never merged away; the message that broke the run is stashed (with its
  original sender) and handled on the next loop iteration. Verified: `verify_drag`
  (drag + close), click-to-focus, and Dock click-to-launch all still pass.

- **Time-driven render loop (v1.1.x perf pass):** the compositor is now a
  *persistent-scene* compositor with the render rate **decoupled from the input
  rate**, the standard model for tear/judder-free desktops (Wayland/Quartz). Input
  and app handlers only **update window state and record damage** (`mark_dmg` /
  `mark_full`); they never paint. A forked **render ticker** child blocks on a real
  timer (`msleep`, a new `SYS_SLEEP` backed by a PIT-driven sleeper queue in the
  scheduler — no busy-wait) and sends the server a `WM_TICK` at a steady ~60–100 Hz.
  Each tick, `render_frame` paints **one** frame from the accumulated damage (full
  recompose, or the clipped `compose_dmg` + cursor restore for partial damage), and
  a clean frame (no damage, cursor unmoved) is **skipped entirely**, so an idle
  desktop does no work. This gives steady frame pacing regardless of how fast the
  mouse streams events, and removes the input-driven "render storm". The damage
  model is preserved (a moving window still costs only its footprint per frame).
  Verified: `verify_drag` (drag + close), click-to-focus + type, Dock
  click-to-launch, the menu dropdown, and the leak stress test all pass.

  Note on tearing: we still write straight to VRAM with no vblank sync, so true
  *tearing* would need vsync — but QEMU's emulated VBE exposes no vblank and
  samples the framebuffer on its own timer, so it does not manifest here. The
  render loop is about frame **pacing** and decoupling, not vsync.

  Remaining lever (not yet done): **per-window surface caching** (skip redrawing
  windows whose content did not change) is the next step — with the background and
  the render storm gone, this is what makes complex drag/resize cost-free.

**Keyboard pipeline** (closing the loop keyboard → windowserver → app → screen):
the windowserver forks a small helper child that blocks on the console
(`read(0)`) and forwards each key as a `WM_KEY` message; the windowserver routes
it to the focused (top-most) window's owner app; the app updates its surface and
calls `PRESENT`. `init` picks the session by output device — `fb_active()` true →
windowserver + Terminal (no text shell, which would be invisible); false → the
text shell exactly as before. The Terminal app is event-driven: it echoes typed
keys into a small transcript and repaints on each keystroke.

**Not "done" until it runs in real QEMU.** The core (windows, z-order, focus,
draw, composite) is PNG-verified, but the live loop — windowserver `fb_map`s the
framebuffer, the keyboard child reads real input, the Terminal redraws on screen —
needs an on-screen boot to confirm. It builds clean and runs once there is a live
framebuffer (`make run-vbe`/`gui`). Surface transport is server-side draw commands
for now; client-side shared-memory surfaces are a later upgrade. PS/2 mouse +
cursor, click-to-focus, window dragging and a Dock process follow the first live
run.
