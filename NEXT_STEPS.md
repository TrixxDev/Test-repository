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

## Phase 9 — Graphics (Branch B, the macOS feel) — NEXT

Build the layering correctly from day one — apps never draw to the framebuffer
directly:

```
app → window server → compositor → framebuffer
```

- **9.0 — Framebuffer.** Leave VGA text mode. Get a linear RGB framebuffer
  (VBE/VESA now; GOP later if/when UEFI). Target 1024×768+ ; expose it as a
  device the compositor owns.
- **9.1 — 2D graphics library.** pixel, rect, rounded rect, alpha blending,
  text rendering (a bitmap/edge-AA font), and a PNG decoder for assets.
- **9.2 — Compositor + Window Server.** `app → window server → compositor →
  framebuffer`. Apps render into off-screen surfaces; the compositor owns the
  screen. This boundary is the single most important macOS-like decision.
- **9.3 — Aurora Desktop.** First desktop: top menu bar, Dock, wallpaper, mouse
  cursor — even before real windows.
- **9.4 — Windows.** Move/drag, minimise, close, focus.
- **9.5 — Finder analogue (`Aurora Files`).** A real GUI app over the VFS
  (needs FS write — now available).
- **9.6 — Design system.** 12–16px corner radii, translucency, shadows, blur,
  smooth animations. This is where the "macOS feel" actually appears.

Mouse (PS/2) input is routed through the window server (added around 9.3/9.4).

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

## Suggested immediate next action

Boot-test the FS-write demo in QEMU (`make run`, then `save /disk/NOTE.TXT hello`
→ `cat /disk/NOTE.TXT`). Then start **Phase 9.0 — framebuffer**: switch the boot
into a linear-framebuffer video mode and stand up a minimal `gfx` surface, so the
compositor and desktop have something to draw on.
