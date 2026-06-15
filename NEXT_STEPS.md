# AuroraOS — Next Steps

Forward plan and the reasoning behind the ordering. Status of what's done:
[CURRENT_STATUS.md](CURRENT_STATUS.md). Full roadmap: [ROADMAP.md](ROADMAP.md).

## Guiding rule

Keep the architecture clean over chasing features. New subsystems (network,
graphics, assistant) should be **userspace services** that talk over IPC, not
kernel code. Do not start graphics until there is a stable network daemon,
sockets, filesystem writes, and a minimal service model — otherwise the GUI has
nothing solid to live on.

## Phase 8 — Networking

Build it as userspace services over IPC, not inside the kernel.

- **8A — loopback — DONE (v0.8.0).** Kernel `struct socket` endpoints
  (`AF_LOOPBACK`), `socket`/`sock_link`/`poll` syscalls, and a `netd` daemon
  that owns ports and brokers bind/connect/accept over message IPC. Verified
  end to end by `echosrv`/`echocli` (client → netd → server → back). See
  [docs/NETWORKING.md](docs/NETWORKING.md).
  - [x] socket API (kernel mechanism + IPC RPC to `netd`)
  - [x] loopback endpoint pair with blocking recv/send + EOF
  - [x] `poll()` readiness wait
  - [ ] follow-ups: real `poll` timeouts (tick-driven), poll ops for
    pipe/console, datagram (`SOCK_DGRAM`) sockets, in-QEMU boot test of the demo
- **8B — Ethernet/IP — next.** Same daemon boundary:
  `app → IPC → netd → driver → hardware`.
  - [ ] Ethernet driver (e.g. virtio-net or rtl8139 in QEMU)
  - [ ] ARP → IPv4 → UDP → TCP → DNS, in that order (loopback addr `127.0.0.1`
    routed through the existing socket API)
  - [ ] HTTP only after the above

Out of scope for Phase 8 (deferred): TLS, HTTPS, IPv6, DHCP, Wi-Fi.

Rationale: most hobby OSes start at TCP and suffer; loopback + a daemon
boundary keeps the stack testable and the kernel small.

## Other near-term debts (pick up alongside 8)

- **Security — rwx on VFS nodes (next security step).** The uid foundation
  exists (per-process uid, `getuid`/`setuid`, root vs uid 1000, `sock_link`
  gated to root). Next: add owner-uid + mode bits to `vfs_node_t`, set them
  when nodes are created (tmpfs/fat32/console/socket), and enforce in
  `sys_open`/`exec`/`write`. Doing this while processes are few is much easier
  than after the network grows.
- **Filesystem writes:** FAT32 is read-only. Add write support (or a writable
  on-disk FS) + a block cache. Needed for persistence and many services.
- **Real signals:** shutdown is currently a `"shutdown"` IPC message by
  convention. A minimal signal mechanism (`kill` + handlers) would generalize
  job control and shutdown.
- **Shell features:** multi-stage pipes (`a | b | c`), redirects (`>`, `<`),
  more builtins, a small set of coreutils.
- **libc growth:** more string/stdio, a better allocator (coalescing/splitting).

## Phase 9 — Graphics

Only after netd + sockets + FS writes + a minimal service model.

- Build the right layering from day one — do **not** let apps draw straight to
  the framebuffer:

  ```
  app → window server → compositor → framebuffer
  ```

- [ ] VBE/VESA linear framebuffer (later GOP/UEFI)
- [ ] software rendering: blits, fonts, alpha
- [ ] compositor (overlap, shadows, rounded corners — macOS-like "glass")
- [ ] mouse (PS/2) + input events routed through the window server
- [ ] widgets: windows, buttons, menu bar, a Dock-like panel

## Phase 10 — Desktop & Aurora Assistant

- [ ] window manager + desktop, system apps (terminal, file manager, settings)
- [ ] **Aurora Assistant as a userspace daemon (`aurorad`)**, reached over IPC
      by shell / GUI / file manager — never in the kernel. (AI work is
      deliberately deferred until the platform underneath is ready.)

## Cross-cutting (whenever they block progress)

- Driver model (a uniform device/registration interface).
- Multi-user + permissions + a basic security model.
- SMP / better scheduler (priorities, sleep/timers) if needed.

## Suggested immediate next action

Boot-test the Phase 8A demo in QEMU (`make run`, then `echosrv &` / `echocli`)
to confirm the loopback path interactively, then start **Phase 8B**: add a NIC
driver and the ARP→IPv4→UDP→TCP path behind the existing `netd`/socket boundary.
The rwx-on-VFS security step is a good parallel pickup while process counts are
still small.
