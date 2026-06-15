# AuroraOS — Next Steps

Forward plan and the reasoning behind the ordering. Status of what's done:
[CURRENT_STATUS.md](CURRENT_STATUS.md). Full roadmap: [ROADMAP.md](ROADMAP.md).

## Guiding rule

Keep the architecture clean over chasing features. New subsystems (graphics,
network, assistant) are **userspace services** that talk over IPC, not kernel
code.

**Priority shift — AuroraOS targets a macOS-like desktop.** What a user
perceives as "macOS" is the *visual* layer (window manager, compositor, Dock,
Finder, animations, typography), not TCP/ARP. So the work splits into two
branches:

- **Branch A — infrastructure:** FS write, security, services, *then* network.
- **Branch B — visual environment:** framebuffer → 2D → compositor → desktop.

Branch B starts **earlier** than it would for a classic Unix, because the
desktop is the product. The one infrastructure piece the desktop genuinely needs
first is **filesystem writes** (Finder, settings, Dock state, app data). The
network can wait until after the desktop exists.

### Chosen path from here

```
FS write (done) → Framebuffer → Window Server → Compositor →
Dock + Desktop → Mouse + Windows → Finder → Network
```

## FS write — DONE (v0.8.2)

FAT32 is now read/write. ATA gained sector writes; FAT32 gained cluster
allocation, file create, growing writes (read-modify-write of partial clusters),
and directory-entry/size updates across both FAT copies. `open` supports
`O_CREAT`/`O_TRUNC` (with a parent-directory write-permission check); the `save`
program + `cat` demonstrate persistence. See [docs/VFS.md](docs/VFS.md).

- [x] `ata_write_sectors` + cache flush
- [x] FAT32 write/create/grow/truncate, FAT + dirent updates
- [x] `open(O_CREAT|O_TRUNC)`, `save` userspace tool
- [ ] follow-ups: file delete + cluster freeing (truncate currently leaks the
  tail of the chain), subdirectory create, a block cache, persisted owner/mode
  (FAT perms are synthetic and reset on remount), in-QEMU boot test

## Phase 9 — Graphics (Branch B, the macOS feel) — IN PROGRESS

Build the layering correctly from day one — apps never draw to the framebuffer
directly:

```
app → window server → compositor → framebuffer
```

- **9.0 — Framebuffer — DONE (v0.9.0).** Multiboot 1024×768×32 linear mode;
  `drivers/fb.c` maps the loader-provided framebuffer into a `gfx_surface_t`,
  gated so text mode still works without one. See [docs/GRAPHICS.md](docs/GRAPHICS.md).
- **9.1 — 2D graphics library — minimal DONE (v0.9.0/9.1).** `kernel/gfx.c`:
  rects, rounded rects, circles, vertical gradient, blit, and an **8×16 bitmap
  font** (`kernel/font8x16.h` via `tools/genfont.py`). Plus a **static desktop**
  (`kernel/desktop.c`: wallpaper + labelled menu bar + clock + lettered Dock),
  rendered to a PNG via `make screenshot`.
  - [ ] still to do for 9.1: alpha blending, a PNG/image decoder for assets.
- **9.0.5 — Live output — DONE in code (v0.9.1), needs on-screen confirm.** Two
  ways to bring up a real framebuffer: the Bochs/std-VGA VBE fallback
  (`make run-vbe`, programs the DISPI regs + finds the LFB via PCI) and a GRUB
  Multiboot-framebuffer ISO (`make iso`). **Open item:** actually see the Dock on
  a QEMU screen and confirm framebuffer mapping / pitch / mode-switch — this
  cannot be done in the current sandbox (no QEMU/display).
- **9.2 — Window server (event-driven, userspace) — built, core PNG-verified.** A
  real `windowserver` (`user/wserver.c`, registered as `wm`): single-source event
  loop, sole framebuffer writer, full recomposite per `PRESENT`, window IPC
  (`WM_CREATE/DESTROY/MOVE/DRAW_RECT/DRAW_TEXT/PRESENT`). The kernel adds two tiny
  primitives — `fb_map` (hand over the framebuffer) and `fb_active` (so `init`
  picks GUI vs text). **Keyboard pipeline** closed: a forked reader child
  (`read(0)`) → `WM_KEY` → focused window's owner app → redraw; the interactive
  `user/term.c` Terminal echoes typed keys. `init` runs windowserver + Terminal in
  graphics mode (no invisible shell), the shell in text mode. Out of the kernel by
  design:
  ```
  kernel:        framebuffer · input · IPC
  windowserver:  windows · z-order · focus · compositor   (userspace)
  ```
  - [ ] **Not "done" until it runs in real QEMU.** The live loop (framebuffer +
    real keyboard + on-screen redraw) builds clean but needs an on-screen boot;
    it activates once the framebuffer is live (9.0.5).
- **9.3+ — pointer, focus, drag — design ready, implement after the live gate.**
  The mouse/cursor/click-to-focus/drag architecture is specified in
  [docs/INPUT.md](docs/INPUT.md): PS/2 mouse → IRQ12 → a kernel read source →
  windowserver reader child → `WM_MOUSE` → cursor + hit-test + focus + drag, all
  full-recomposite. **The PS/2 driver and IRQ routing are intentionally NOT
  written until 9.2 is confirmed on a real screen** — hardware/IRQ code built
  blind would be wasted if the framebuffer behaves differently than assumed.
  Order: **9.3** cursor → **9.4** click-to-focus → **9.5** window dragging (the
  headline: grab a window by its title bar and move it) → **9.6** Dock as its own
  process → **9.7** Launcher/Finder.

Deferred until the desktop feels real (per the agreed priority): client-side
shared-memory surfaces, animations, and the network stack. The current
`app → IPC → windowserver → framebuffer` path is enough for the first windows.

## Phase 8B — Networking (Branch A, deferred until after the desktop)

Still the right design (userspace `netd`, `app → IPC → netd → driver → hw`), but
intentionally **after** the visual stack for a desktop-first OS.

- [ ] NIC driver: **virtio-net** (preferred over rtl8139 — simpler, faster, less
  legacy cruft).
- [ ] ARP → IPv4 → UDP → TCP → DNS, in that order, behind the existing socket
  API. TCP will likely take longer than the whole loopback phase.
- [ ] HTTP only after the above. Out of scope: TLS, HTTPS, IPv6, DHCP, Wi-Fi.

## Phase 10 — Desktop apps & Aurora Assistant

- [ ] system apps (terminal, settings) on top of the window server.
- [ ] **Aurora Assistant as a userspace daemon (`aurorad`)**, reached over IPC —
  never in the kernel. (AI work stays deferred until the platform is ready.)

## Other near-term debts (pick up when they block progress)

- **Security — extend the model:** `gid`/groups, a login/user database,
  permissions persisted by the FS, restricting `kill`/`msgsend` across uids.
- **Real signals:** shutdown is a `"shutdown"` IPC message by convention; a
  minimal signal mechanism would generalise job control and shutdown.
- **Shell features:** multi-stage pipes (`a | b | c`), redirects (`>`, `<`).
- **libc growth:** more string/stdio, a coalescing allocator.
- **Driver model / SMP / better scheduler** — when they start to bite.

## Two tracks (per the agreed rule)

- **Architecture (no QEMU needed, verify via PNG):** the window server model,
  surfaces, z-order compositor and window IPC protocol — done for 9.2
  (`make screenshot-wm`). Next architectural pieces could be a mouse *event*
  model and a Dock/app process model, still PNG-verifiable.
- **Hardware (needs a real run):** the live framebuffer (`make run-vbe`/`gui`),
  then framebuffer-to-userspace mapping + shared-memory surfaces to turn the
  compositor into a live `windowserver` process, then PS/2 mouse. **Rule: no GUI
  stage counts as done until it has run once in real QEMU.**

## Suggested immediate next action

**Confirm 9.2 on a real QEMU screen** (`make run-vbe`, or `make gui`) — see the
checklist in [docs/GRAPHICS.md](docs/GRAPHICS.md): Terminal window appears, typing
shows text, focus works, no recomposite artifacts. That gate is the only thing
between here and 9.3. The 9.3 input architecture is already specified
([docs/INPUT.md](docs/INPUT.md)); the PS/2 driver gets written once the gate is
green.
