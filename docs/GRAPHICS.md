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
mode. If the loader supplies one, `multiboot_info_t` carries
`framebuffer_addr/pitch/width/height/bpp/type`; `fb_init()` identity-maps the
region and wraps it in a `gfx_surface_t`. If no framebuffer is supplied (e.g.
QEMU's bare `-kernel` loader may ignore the request), the kernel simply stays in
VGA text mode — the graphics path is fully gated, so the text boot is unaffected.

> Live-on-hardware note: a framebuffer appears when booted by a Multiboot
> framebuffer-capable loader (e.g. GRUB). Booting `qemu -kernel` directly may not
> provide one; a Bochs-VBE/PCI mode-set fallback is a planned addition. The
> rendering itself is verified off-screen (see below).

## 9.1 — 2D library (`kernel/gfx.c`)

Pure, portable software rendering over a linear 32-bpp surface
(`gfx_surface_t { pixels, width, height, pitch, bpp }`), colors `0x00RRGGBB`:

- `gfx_clear`, `gfx_fill_rect`, `gfx_draw_rect`
- `gfx_fill_round_rect` (quarter-circle corners), `gfx_fill_circle`
- `gfx_fill_vgradient` (per-scanline channel interpolation)
- `gfx_blit` (copy an image rectangle)

No alpha blending or fonts yet — those come with the design system (9.6). The
same code runs in the kernel and on the host.

## First desktop (`kernel/desktop.c`)

`desktop_render(surface)` paints, with shapes only:

- a blue→violet gradient **wallpaper**,
- a light **menu bar** with a logo accent and status pills + a hairline
  separator,
- a dark rounded **Dock** centered at the bottom with five rounded app icons.

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

## Next (9.2+)

- Window server + compositor: apps draw into off-screen surfaces; the compositor
  owns the screen (`app → window server → compositor → framebuffer`).
- PS/2 mouse + input events routed through the window server.
- Then windows (move/focus/close), a Finder-like file app, and the design system
  (rounded corners, translucency, shadows, blur, animations, fonts).
