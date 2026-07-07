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
  - [x] **Confirmed live in QEMU (v0.9.5).** The framebuffer comes up (Bochs-VBE),
    the windowserver paints the desktop, the Terminal window opens, and typed keys
    flow keyboard → windowserver → focused app → on-screen redraw. Captured
    headlessly with `make verify-gui` (`aurora_live_typed.png` shows the echoed
    input). This unblocked a real bug — the PMM was not reserving the Multiboot
    info/mmap/cmdline, so the framebuffer never activated; see CURRENT_STATUS.md.
- **9.3 — pointer + cursor + click-to-focus — DONE (v0.9.6), live-confirmed.**
  Implemented per [docs/INPUT.md](docs/INPUT.md): kernel PS/2 mouse driver
  (`drivers/mouse.c`) + IRQ12 → `SYS_MOUSE` → a windowserver reader child →
  `WM_MOUSE` → cursor (drawn on top each recomposite) + hit-test (`wm_window_at`)
  + click-to-focus (`wm_raise`, focus follows z-order). Verified on screen with
  `make demo-focus` (`aurora_live_focus.png`: clicking the back Terminal raises it
  and typing lands in it). Text-mode boot unaffected.
- **9.4/9.5 — window dragging + close button — DONE (v0.9.7), live-confirmed.**
  The windowserver's `WM_MOUSE` handler runs a drag state machine
  (`drag_state_t` in `user/wserver.c`): press in a title bar records the window +
  cursor-to-origin offset, motion while held re-places it via `wm_move_clamped`
  (clamped so a graspable strip stays on-screen and the title bar never goes under
  the menu bar), release ends the drag. A press on the red title-bar button
  (`wm_in_close_button`, drawn with a dark "×") destroys the window (`wm_destroy`)
  and tells its owner to exit via `WM_DESTROY`. Verified on the live framebuffer
  with `make demo-drag` / `make demo-close` (+ pixel asserts in
  `tools/verify_drag.py`).
- **9.5.1 — damage-driven compositor — DONE (v0.9.8).** The scene composites into
  an off-screen back buffer (`wm_compose`); only changed rectangles are pushed to
  the framebuffer. A pointer move no longer repaints the whole screen; output is
  pixel-identical to a full repaint.
- **9.6 — Dock as its own process — DONE (v0.9.9), live-confirmed.** The Dock
  (`user/dock.c`) left `desktop.c` and became the first standalone GUI client: a
  borderless `WM_F_DOCK` window the server pins bottom-center, keeps always on top,
  and excludes from keyboard focus, with color-key transparency for the rounded
  panel. The server forwards pointer events to the window under the cursor
  (`WM_POINTER`); the Dock highlights the hovered icon and launches apps on click
  (double-`fork`+`exec`). Verified with `make demo-dock`.
- **9.7 — Finder (`Aurora Files`) — DONE (v0.9.10), live-confirmed.** The first GUI
  app that reads the filesystem. A new `readdir(path, index, struct dirent*)`
  syscall exposes the VFS to user space (permission-checked like `open`, no special
  rights); `user/files.c` lists `/disk`, selects a row on click, and opens it on a
  second click (enter a directory / `..` up / exec an `.ELF` / hand other files to
  the Viewer in 9.8). It reuses the Dock's `WM_POINTER` plumbing for row hits and
  the double-`fork`+`exec` spawn pattern. Verified with `make demo-files` (opens
  from the Dock's Files icon, lists `/disk`, double-clicks `TERM.ELF` to launch a
  Terminal).
- **9.8 — Text Viewer — DONE (v0.9.11), live-confirmed.** `user/viewer.c` is the
  app the Finder hands non-`.ELF` files to: it `open`/`read`/`close`s the file
  (capped at `VIEWER_MAX_FILE` = 64 KiB), splits it into lines (LF/CRLF) and draws
  them with the 8×16 font, scrolling with the arrow keys / PgUp/PgDn / j-k-space.
  This required the keyboard driver to decode `0xE0` **extended scancodes** into
  shared `KEY_*` codes (`include/keys.h`) that flow through the existing char
  pipeline → `WM_KEY`. Verified with `make demo-view` (the Finder opens `ABOUT.TXT`
  in the Viewer, then PgDn scrolls it). This closes the **Dock → Finder → file →
  Viewer** chain — the GUI now works with user *data*, not just windows.
- **9.9 — Stabilization audit → v1.0.0 — DONE.** A memory/process/IPC sweep before
  building more on top: fixed the window content-buffer leak (heap proven flat
  across stress rounds), the free-on-full-table leak, added dead-owner window
  reaping and a `WM_DESTROY` ownership check; verified zombie-free process reaping,
  graceful window-table limit, mailbox-overflow drop, and Finder close/relaunch.
  Tooling: `user/wmstress.c` + `make stress`. Full write-up:
  [docs/STABILITY.md](docs/STABILITY.md).

Deferred until the desktop feels real (per the agreed priority): client-side
shared-memory surfaces, animations, and the network stack. The current
`app → IPC → windowserver → framebuffer` path is enough for the first windows.

## Phase 8B — Networking — DONE, ran ahead of this doc

This section originally deferred networking until after the desktop and scoped
TLS/HTTPS out entirely. In practice the network/security arc (virtio-net → ARP
→ IPv4 → UDP/TCP → DNS/DHCP, then a from-scratch TLS 1.3 + X.509 + HTTP(S)
client through HTTP/2) ran as its own track and is now feature-complete —
tracked phase by phase in [docs/SECURITY.md](docs/SECURITY.md), not here. HTTP/2
was declared "practically complete, API frozen" at phase 17.5.2, closing that
arc and opening the 18.x track below. This doc (and [CURRENT_STATUS.md](CURRENT_STATUS.md))
were not kept current during that arc; treat docs/SECURITY.md as authoritative
for anything past phase ~10.

## Phase 18.x — Kernel I/O & Scheduling — DONE (opened after 17.5.2 closed HTTP/2)

The bugs found while hardening HTTP/2 (17.5.1/17.5.2) stopped being "RFC X not
implemented" and started being two already-correct mechanisms interacting
badly (a missing duplicate ACK, cookies not flowing back over h2, a test
harness closing a socket before a slow peer finished reading). That's a sign
the web-client stack is mature enough that the next real gains are in the
kernel's execution model, not another protocol.

- [x] **18.0 — Serial command channel for tests.** `drivers/serial.c` gains
  RX (IRQ4) merged into the console alongside the keyboard, so QEMU tests type
  commands as raw bytes over a socket-backed serial chardev instead of
  scancode-injecting through the monitor's `sendkey`. See
  [CURRENT_STATUS.md](CURRENT_STATUS.md)'s phase table and
  `tools/qemu_serial.py`.
- [x] **18.1 — Wait queues + sleep/wakeup.** `wait_queue_t` + `wait_event_timeout()`
  generalized the single-waiter block/wake pattern; console/pipe/socket all
  migrated onto it.
- [x] **18.2 — Non-blocking I/O model.** `O_NONBLOCK` + `EAGAIN`/`EWOULDBLOCK`,
  an `EINTR` contract (defined, unused until Aurora has signals), all
  console/pipe/socket paths migrated.
- [x] **18.3 — `poll()`/`select()`-style multi-source wait.** `sys_wait_events()`
  + a libc wrapper, built on 18.1/18.2.
- [x] **18.4 — TCP sliding window + out-of-order reassembly.** Multiple
  segments in flight, out-of-order splicing, real receive-window management.
- [x] **18.5 — Performance Characterization (reframed from "ChaCha20-Poly1305
  optimization" once actually measured).** 17.5.2's ~1.2-1.5 KB/s figure was a
  single anecdotal data point, not a profile — 18.5.2/18.5.3 added kernel- and
  userspace-side counters (AEAD, HPACK, HTTP/2 framing, `tcp_input`/`tcp_tick`,
  wait blocks), and 18.5.3.1 ran a ten-scenario sweep (size/protocol/setup/reuse)
  against them. Verdict: AEAD is 0.026% of wall time at 5 MB — the standing
  "optimize ChaCha20-Poly1305 next" plan this section used to state was wrong,
  and is retired. 18.5.4 traced the sweep's own leftover mysteries (150-175
  `wait_blocks`/DATA-frame, 145K-vs-9 `tcp_tick_calls`) to a real bug — an
  unconditional busy-spin in `tcpsock_close()`'s teardown wait — found,
  confirmed protocol-agnostic, and fixed (same `wait_event_timeout()`
  discipline `tsk_read()`/`tsk_write()` already had). 18.5.5 then cleared the
  IRQ/driver path and receive-window management as explanations too (measured,
  not assumed: `rx_irqs≈rx_packets`; the window closed for 273µs total out of a
  21.5s transfer). Every layer inside Aurora's own client stack is now cleared;
  what's left is outside the guest (QEMU `slirp` latency, or the Python test
  servers' own send pacing) — see docs/SECURITY.md's "Step 18.5" for the full
  trace. Tracked separately, not blocking: **"Throughput under QEMU/slirp"** —
  run the same Python server/QEMU/slirp path with a Linux guest's `curl` in
  Aurora's place; if it's similarly slow, the environment is the answer and
  this closes for good, otherwise a real stack difference exists worth chasing.

## Phase 19 — Platform Hardening & Desktop Maturity (opened after 18.5 closed the network arc)

With process/VM/IPC/VFS, a GUI + window server, TCP/IP, TLS 1.3, and HTTP/1.1
plus HTTP/2 all working, the highest-value work is no longer "another
protocol" -- it's raising the quality of the whole platform. Priority order
(highest first), each independently valuable and not blocking the others:

- [x] **19.1 — Guard pages.** Every kernel stack gets its own page-mapped
  slot with an unmapped guard page below it, plus a task-gate double-fault
  handler so an overflow that lands exactly on ESP still gets a diagnostic
  instead of a silent triple-fault reset. See docs/SECURITY.md "Step 18.5.6".
  Directly motivated by a real bug this project already hit once
  (`fs/fat32.c`'s `fat_write_impl`/`fat_update_dirent` double-buffer
  overflow, fixed at the time with no protection added).
- [x] **19.2 — Stack canaries.** DONE, three layers (see docs/SECURITY.md
  "Step 19.2"): `-fstack-protector-strong` kernel- and userspace-wide with
  a freestanding runtime (arch/i386/stack_protector.c, user/libc/ssp.c);
  a PER-THREAD canary value (hash of boot-TSC seed/tid/stack base, no
  rand()) that do_switch() swaps into `__stack_chk_guard` at every context
  switch, Linux-!SMP-style; and a stack-END canary word directly above
  19.1's guard page, checked at context switch / syscall exit /
  thread_free. Plus a `kstack_max_used` high-water-mark counter in
  kernel_prof (profstat), sampled at switch points. Acceptance:
  tools/canary_qemu.py (userspace smash -> child exits 134, OS survives;
  kernel smash -> "KERNEL STACK SMASHING DETECTED" halt, provably the
  canary and not the guard page).
- [ ] **19.3 — Shared-memory surfaces + Clipboard.** The single biggest
  desktop-experience win available: replace the window server's per-frame
  IPC-then-copy-into-VRAM path with an app-owned shared framebuffer +
  damage-rect handoff (less `memcpy`, smoother GUI, and the prerequisite
  for anything video/media-shaped later). Clipboard
  (`WM_CLIPBOARD_SET`/`GET`, one bounded string, last-writer-wins) is
  small enough to land alongside it and closes a real gap (copy/paste
  across apps doesn't exist yet).
- [ ] **19.4 — SDK / ABI freeze.** Declare "Aurora SDK v1" (libc, libgui,
  libsock, libtls) and guarantee compatibility, so applications can start
  living independently of kernel churn.
- [ ] **19.5 — Developer tools.** `perf top`/`record`/`stat` (the counters
  already exist, from 18.5.2/18.5.3/this phase); a minimal debugger
  (`ps`/`attach`/`bt`/`regs`/`memory`); `trace` (`open`/`tcp`/`sched`, ...).
- [ ] **19.6 — FS maturity.** Long file names; `mmap()`; a page cache (once
  in, `cat`/the browser/the editor all get faster for free).
- [ ] **19.7 — Network infrastructure** (only after the above, and no more
  new protocols first): DNS cache eviction/TTL polish, TCP fast
  retransmit, `sendfile()`, zero-copy.

Deliberately NOT next (per the same discussion): more application-layer
protocols (already have HTTP/1.1 + HTTP/2 + TLS 1.3), SMP (large, not
urgent), a mini-browser (fun, but wants 19.3/19.4 underneath it first).

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

Superseded by Phase 19 above (the desktop track's remaining items --
Clipboard, shared-memory surfaces -- are now 19.3, sequenced after the
kernel-hardening work that directly follows a bug this project already
hit): networking (8B) and HTTP/1.1+HTTP/2+TLS 1.3 are long since DONE, far
past what this section used to describe, and 19.1 (guard pages) + 19.2
(stack canaries) have both landed -- the kernel-stack memory-safety model
is now: guard page (past-the-end), task-gate #DF (ESP-invalid), compiler
canary (in-frame), stack-end canary (bottom word), watermark counter
(depth trend). **Next: 19.3 — shared-memory surfaces + Clipboard**, the
big user-visible desktop push.
