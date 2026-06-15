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
- **8A.5 — security foundation — DONE (v0.8.1).** Done *before* the network
  widens the attack surface: per-process uid + `getuid`/`setuid`/`uid_of`; rwx +
  owner on VFS nodes enforced at `open`/`exec`; service-registry permissions
  (lookup gated, no name hijack); privileged ports (<1024) root-only in netd.
  See [docs/VFS.md](docs/VFS.md), [docs/IPC.md](docs/IPC.md).
- **8B — Ethernet/IP — next.** Same daemon boundary:
  `app → IPC → netd → driver → hardware`.
  - [ ] NIC driver: **virtio-net** (preferred over rtl8139 — simpler, faster,
    less legacy cruft; rtl8139 only as a learning aside).
  - [ ] ARP → IPv4 → UDP → TCP → DNS, in that order, behind the existing socket
    API. TCP will likely take longer than the whole loopback phase.
  - [ ] HTTP only after the above

Out of scope for Phase 8 (deferred): TLS, HTTPS, IPv6, DHCP, Wi-Fi.

Rationale: most hobby OSes start at TCP and suffer; loopback + a daemon
boundary keeps the stack testable and the kernel small.

## Other near-term debts (pick up alongside 8)

- **Security — extend the model.** The foundation is in (uid, VFS rwx, service
  perms, privileged ports — see 8A.5 above). Next, when justified: a `gid` +
  group bits; a real login / user database; permissions persisted by a writable
  FS; and restricting `kill`/`msgsend` across uids if it becomes a concern.
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

Boot-test the Phase 8A/8A.5 demo in QEMU (`make run`, then `id`, `echosrv &`,
`echocli`) to confirm the loopback path and the new permission checks
interactively. Then start **Phase 8B**: a **virtio-net** driver and the
ARP→IPv4→UDP→TCP path behind the existing `netd`/socket boundary, with the
security model already in place.
