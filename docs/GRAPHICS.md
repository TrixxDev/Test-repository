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

- **Per-window surface caching — windows are real surfaces (v1.1.x perf pass):**
  each decorated window now owns a server-side **presentation surface** that holds
  its fully-composed pixels (drop shadow + rounded panel + title bar + traffic
  lights + title + content). `wm_refresh_surfaces` rebuilds that surface **only
  when the window is `dirty`** — i.e. its content changed (`WM_PRESENT`), it was
  shaded, or it was resized (maximize) — not every frame. Compositing a window is
  then a single `blit_keyed` of the cached surface (the footprint is color-keyed,
  so corners + the shadow's L-gap stay transparent). So a drag/move/raise no longer
  re-renders any chrome: the window travels as a finished bitmap, the same model as
  Wayland/Quartz surfaces (here with 1-bit alpha via the color key). The server
  owns the presentation buffer like it owns the content buffer (allocated in
  `WM_CREATE`, realloc'd on maximize, freed on destroy — the leak test confirms a
  flat heap). The host PNG renderer keeps the immediate path (no cache attached →
  `wm_draw_window` draws in place). Verified pixel-identical: `verify_drag`
  (drag + close), boot, click-to-focus + type, shade, maximize, and the menu all
  match. **Remaining levers** are now hardware-facing only — shared-memory client
  surfaces (so apps render into the cache directly) and a virtio-gpu/vsync path —
  both deferred.

- **Shared-memory surfaces — zero-copy client rendering:** a GUI client can render
  straight into the buffer the server composites from, instead of sending a
  `WM_DRAW_*` message per shape. A small kernel SHM pool (`kernel/shm.c`) backs each
  surface with physical frames that can be mapped into more than one address space
  at the same virtual address (`shm_create`/`shm_map`/`shm_destroy`, syscalls
  35–37). On `WM_CREATE` with `WM_F_SHM` the server allocates the content surface as
  an SHM object, maps it as the window's content, and returns the id; the client
  maps the same id and draws into it with the gfx library, then sends a single
  `WM_PRESENT` (damage only). The compositor path is otherwise unchanged — it blits
  from the content surface as before, so per-window caching, color-key transparency
  and damage all still apply. **Lifecycle (no double free):** shared frames' PTEs
  carry a `PAGE_SHARED` bit, so `vmm_destroy_address_space` *unmaps* but never frees
  them when a mapper exits; the frames are released exactly once — by the server's
  `shm_destroy` on window destroy, or by `shm_release_pid` if the creator dies. The
  **Dock** is the first client converted (fixed-size, borderless — no resize/maximize
  complications, and it redrew the whole panel + icons on every hover, so it emitted
  the most per-frame draw IPC). Verified: the Dock renders pixel-for-pixel as before
  and still launches apps on click; the `PAGE_SHARED` change is leak-free across 50+
  window create/destroy cycles in the stress test; 100 % host renders + `verify_drag`
  are unaffected. (Decorated, resizable clients can adopt shared surfaces later;
  that needs an SHM realloc on maximize, deferred.)
- **Display resolution — runtime mode switching:** the resolution is selectable in
  **Settings → Display** (800×600 / 1024×768 / 1280×720 / 1366×768 / 1920×1080),
  saved as `resolution=WxH` in `/disk/settings.cfg`. It works because the boot path
  here is the Bochs/QEMU VBE interface, whose mode can be re-set at runtime (the
  linear-framebuffer BAR is stable across modes). A new root-only syscall
  `fb_set_mode(w,h)` (#34) re-runs the VBE mode-set and re-maps the framebuffer at
  the new geometry; on a fixed GRUB/Multiboot framebuffer it returns 0 (no change).
  The window server applies the saved resolution at startup (before it maps the
  framebuffer, so apps come up at the right size) and **live** on
  `WM_RELOAD_SETTINGS`: `do_resize` re-sets the mode, re-maps (`fb_map`), reallocates
  the back buffer + background cache, clamps the cursor and every window back
  on-screen, re-pins the Dock to the new bottom-center, and repaints — all without a
  reboot. Verified: a 100 % default boot is byte-/pixel-identical (no `resolution`
  key → no switch); booting at 1280×720 and 1920×1080 comes up at that mode; a live
  1024×768→1280×720 switch via Settings re-lays-out the whole desktop with no crash
  or corruption; the leak test stays flat. (Under a fixed GRUB framebuffer the
  picker is a no-op — the mode is owned by the loader.)
- **UI scale — app content (staged, step 2 of 2):** the apps are now scale-aware,
  so the **whole** desktop scales together (not just the chrome). Delivery is by a
  **new syscall**: the kernel holds the canonical scale (`SYS_UISCALE`), the window
  server (root) publishes it on every settings load (`ui_scale_set`), and apps read
  it (`ui_scale()`) to lay out their content; the server also renders `WM_DRAW_TEXT`
  at the current scale (`wm_draw_text` → `gfx_draw_text_s`), so app text grows to
  match. Each app (`term`, `files`, `viewer`, `settings`, `dock`) multiplies its
  layout metrics by the scale and requests a scaled content size at creation, so a
  freshly-opened window at 150 %/200 % is fully scaled (bigger window, bigger text,
  same row/column counts). Live changes are pushed to apps with a `WM_SCALE` poke
  (broadcast from `WM_RELOAD_SETTINGS`); an app re-queries `ui_scale()` and re-flows
  **within its current surface** (no app-requested resize yet), so an already-open
  window re-flows its text immediately but keeps its pixel size until reopened — a
  freshly-opened one is ideal. The Dock is created once at boot and never recreated,
  so its surface is allocated for the largest scale and the panel is drawn
  bottom-center within it, making it correct at any scale (boot or live) with no
  realloc. Verified: 100 % host renders + boot byte-/pixel-identical, `verify_drag`
  passes, the dock still launches apps at 100 %, a 150 % boot scales the entire
  desktop (Terminal/Finder text, Dock and all), the Finder opens + lists + is
  clickable at 150 %, a live 100 %→150 % change re-flows every app, and the leak
  test stays flat (`round1 == round2`).
- **UI scale — chrome (staged, step 1 of 2):** the desktop has a UI-scale setting
  (100 / 125 / 150 / 200 %), chosen in **Settings → Display** and saved as
  `ui_scale=` in `/disk/settings.cfg`. The scale percent is a single source of
  truth in `desktop.c` (`desktop_set_scale`/`desktop_scale`); the window server and
  `wm.c` read it so everything agrees. The bitmap font gains nearest-neighbor
  scaled variants (`gfx_draw_text_s`, `gfx_text_width_s`, `gfx_font_{w,h}_s`): each
  8×16 cell is scaled to `(8·s)×(16·s)`, and **`scale == 100` is byte-identical to
  the unscaled calls** (the plain `gfx_draw_*` are now thin wrappers over them, and
  the host PNG renderers — which never set a scale — are unchanged). This step
  scales the **server-drawn chrome** uniformly: the menu bar + its text and clock
  (`desktop.c`), the window title bar height, traffic-light positions/radii, corner
  radius and centered title (`wm.c`, via `wm_titlebar_h()`), and the Aurora system
  menu + dropdown (`wserver.c`). App **content** stays native for now (the
  Terminal/Finder/Viewer text), so a high scale shows large chrome around
  native-size content — step 2 makes the apps scale-aware so the whole desktop
  scales together. Changing the scale is **live** (`WM_RELOAD_SETTINGS` re-reads the
  file and `wm_mark_all_dirty` rebuilds every window's surface); to make a live
  change never reallocate, presentation buffers are sized for the **largest** scale
  up front (`wm_present_footprint`, reserving the tallest title bar), so a taller
  title bar always fits the existing buffer. Verified: 100 % host renders + boot are
  byte-/pixel-identical, `verify_drag` still passes, a 150 % boot scales the chrome
  with native content, and a live 100 %→150 % change via Settings rescales every
  window's title bar in one frame with no crash and no leak (`round1 == round2`).

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
