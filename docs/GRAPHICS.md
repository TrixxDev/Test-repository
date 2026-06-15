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

## 9.2 — Window server + compositor (architecture, PNG-verified)

Built as portable userspace code (`user/wm.c` + `user/wm.h`), **not** in the
kernel:

- **Surface model.** Each app renders into its own `gfx_surface_t` (an off-screen
  pixel buffer). The compositor never lets apps touch the screen directly.
- **Window chrome.** `wm_draw_window` paints a rounded title bar with the three
  traffic-light buttons, a centered title, a drop shadow, and blits the app's
  content surface.
- **Z-order compositor.** `wm_composite` paints the desktop, then the windows
  back-to-front by `z`, so overlapping windows stack correctly.
- **Window IPC protocol.** `WM_CREATE / WM_DESTROY / WM_PRESENT / WM_MOVE`
  (`wm_req_t`/`wm_rep_t`) — the contract the future `windowserver` daemon speaks.

Preview (a desktop with two overlapping windows, Files behind Terminal):

```sh
make screenshot-wm     # -> aurora_windows.png
```

**Not done until it runs in real QEMU.** Turning this into a live `windowserver`
*process* needs two kernel primitives first — mapping the framebuffer into
userspace, and shared-memory surfaces between app and server — plus an on-screen
run. Those wait for the first live framebuffer (9.0.5). PS/2 mouse + cursor,
window dragging and a Dock process follow after that.
