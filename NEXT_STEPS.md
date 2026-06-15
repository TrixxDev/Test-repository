# AuroraOS — Next Steps

Forward plan and the reasoning behind the ordering. Status of what's done:
[CURRENT_STATUS.md](CURRENT_STATUS.md). Full roadmap: [ROADMAP.md](ROADMAP.md).

## Guiding rule

Keep the architecture clean over chasing features. New subsystems (network,
graphics, assistant) should be **userspace services** that talk over IPC, not
kernel code. Do not start graphics until there is a stable network daemon,
sockets, filesystem writes, and a minimal service model — otherwise the GUI has
nothing solid to live on.

## Phase 8 — Networking (next)

Build it as userspace services over IPC, not inside the kernel.

- **8A — loopback (`127.0.0.1`)** first, with no NIC at all. This lets us build
  and test the socket API and the stack deterministically before touching
  hardware.
  - [ ] socket-like API (likely new syscalls or an IPC protocol to `netd`)
  - [ ] loopback device + minimal UDP/TCP over it
- **8B — `netd`** as a daemon: `app → IPC → netd → driver → hardware`.
  - [ ] Ethernet driver (e.g. virtio-net or rtl8139 in QEMU)
  - [ ] ARP → IPv4 → UDP → TCP → DNS, in that order
  - [ ] HTTP only after the above

Rationale: most hobby OSes start at TCP and suffer; loopback + a daemon
boundary keeps the stack testable and the kernel small.

## Other near-term debts (pick up alongside 8)

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

Start **Phase 8A**: define the socket/`netd` IPC contract and implement
loopback, so the networking API can be exercised before adding a NIC driver.
