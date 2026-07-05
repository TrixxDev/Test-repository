# AuroraOS — Current Status

Phase-by-phase status of the project. Forward plan: [NEXT_STEPS.md](NEXT_STEPS.md).
Caveats: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

**Current version: v1.1.2** — the desktop environment grows. **Settings** is now a
real app: a Desktop pane picks the **wallpaper** (Aurora Blue/Dark/Purple/Green)
and **accent color** (Blue/Orange/Purple/Green), saved to `/disk/settings.cfg`
(plain `key=value` over the VFS) and applied live (the window server re-reads it on
`WM_RELOAD_SETTINGS` and at boot — the theme **persists across reboots**); a
read-only System pane shows version / RAM / pages / processes / uptime from the
new `sysinfo` syscall. The **Aurora system menu** (v1.1.1) drops down **About AuroraOS**
(opens the Viewer on the about text), **Settings...** (a placeholder app),
**Close All Windows** (closes every window but the Dock) and **Shut Down** (a
"safe to power off" screen + a real `halt` syscall). The menu is drawn by the
window server itself (chrome), so it works even if the Dock or an app has died.
Also (v1.1.0) the **window model is complete**: windows can be **minimized**
(window-shade: collapse to the title bar) and **maximized** (the server reallocs
the surface to fill the screen and sends `WM_RESIZE`; the app redraws — Terminal,
Finder and Viewer are resize-aware), alongside close / focus / drag. The v1.0.0 base remains a full GUI stack (window
server, Dock, Finder, Viewer, Terminal) over a Unix-like kernel, hardened by a
memory/process/IPC **stabilization audit** (see
[docs/STABILITY.md](docs/STABILITY.md)): the window content-buffer leak is fixed
(heap proven flat across stress rounds), apps are reaped with no zombies, the
window table fails gracefully when full, dead apps' windows are reaped, and the
Finder can be closed and relaunched cleanly. Phases 0–7 are implemented and
verified by booting
in QEMU (interactive parts driven via PS/2 input). Phase 8A (loopback sockets +
netd + poll), Phase 8A.5 (security), FS write (FAT32 read/write) and graphics
(framebuffer + 2D library with an 8×16 font + desktop; a userspace, event-driven
**windowserver** with a keyboard input pipeline + interactive Terminal) are
implemented and build clean. **Phases 9.2–9.8 are confirmed live in QEMU**:
the Bochs-VBE framebuffer comes up, the windowserver paints the desktop, Terminal
windows open, typing flows keyboard → windowserver → focused app → on-screen
redraw, the **PS/2 mouse** moves an on-screen cursor + **clicks to focus**
(click a window to raise it; keys then route to it), a window can be
**dragged by its title bar** and **closed with the red title-bar button**, the
**Dock is its own process** — a borderless, always-on-top GUI client that draws
its icons, highlights on hover, and **launches apps on click** — the
**Finder (`Aurora Files`) browses the filesystem** (lists `/disk` via the
`readdir` syscall — the VFS used through ordinary syscalls like the shell, no
special privileges; click selects, a second click opens: enter a directory / exec
an `.ELF`) — and the **Text Viewer renders file contents** (`open`/`read`/`close`
+ the 8×16 font, scrolled with the arrow keys / PgUp/PgDn, now that the keyboard
driver decodes extended scancodes). All captured to PNG via `make verify-gui` /
`make demo-focus` / `make demo-drag` / `make demo-close` / `make demo-dock` /
`make demo-files` / `make demo-view` (drag + close pixel-asserted by
`tools/verify_drag.py`). The compositor is **double-buffered and damage-driven
(v0.9.8)** — events repaint only the rectangles that changed instead of the whole
screen (a pointer move no longer recomposites the desktop), output verified
pixel-identical to the old full repaint. FS write and the rendering/window-server
core are additionally verified on the host (the real `fs/fat32.c` write path +
image re-parse; the real `kernel/gfx.c`/`desktop.c`/`wm.c` rendered to PNGs).

> **v0.9.5 fix.** The live framebuffer was being blocked by a real
> memory-corruption bug: `pmm_init` reserved only the kernel image, not the
> Multiboot structures (info struct, memory map, **command line**) the loader
> leaves in RAM just above it. The first frame allocations clobbered them, so the
> `vbe` command line was read back as garbage (framebuffer never activated) and,
> depending on a given QEMU's structure placement, the boot could reset in a loop.
> `pmm_init` now reserves those regions. The early boot also logs each init step
> so any future early fault names the exact failing step on the serial console.

## Phase status

| Phase | Area | Version | Status |
|-------|------|---------|--------|
| 0 | Bootable kernel (Multiboot, VGA, serial, GDT, IDT, IRQ, PIT, keyboard) | v0.1 | ✅ |
| 1 | Memory (E820, PMM, paging/VMM, kernel heap) | v0.2 | ✅ |
| 2 | Multitasking (TSS, context switch, scheduler, ring 3, `int 0x80`) | v0.2 | ✅ |
| 3 | Storage + processes v2 (ATA, VFS, tmpfs, FAT32, ELF loader, per-process address space) | v0.3 | ✅ |
| 4 | Unix process model (fork/exec/wait/exit, fds, STDIO) | v0.4 | ✅ |
| 5 | Interactive shell + fixed syscall ABI | v0.5 | ✅ |
| 6 | IPC + libc (pipes, dup2, sbrk, printf/malloc/string) | v0.6 | ✅ |
| 7 | Init + service model + message-passing IPC + docs | v0.7 | ✅ |
| 7.1 | Lifecycle hardening (reparent, bg auto-reap, kill, graceful shutdown) | v0.7.1 | ✅ |
| 8A | Loopback sockets (kernel `struct socket`) + `netd` broker + `poll` + uid foundation | v0.8.0 | ✅ |
| 8A.5 | Security foundation: VFS rwx/owner, service-registry permissions, privileged ports | v0.8.1 | ✅ |
| 8.2 | FS write: ATA sector write + FAT32 read/write (create/grow/truncate), `open(O_CREAT/O_TRUNC)` | v0.8.2 | ✅ |
| 9.0/9.1 | Framebuffer (Multiboot) + 2D library + static desktop (wallpaper + menu bar + Dock) | v0.9.0 | ✅ |
| 9.0.5 | Live output: 8×16 text/font; Bochs-VBE fallback (`run-vbe`) + GRUB ISO (`iso`) | v0.9.5 | ✅ live-confirmed in QEMU |
| 9.2 | Event-driven **windowserver** + keyboard pipeline + interactive Terminal; `fb_map`/`fb_active`; frame consistency | v0.9.5 | ✅ live-confirmed in QEMU (`make verify-gui`) |
| 9.3 | **PS/2 mouse + IRQ12** → cursor → hit-test → **click-to-focus** (`SYS_MOUSE`, `wm_window_at`/`wm_raise`) | v0.9.6 | ✅ live-confirmed in QEMU (`make demo-focus`) |
| 9.4/9.5 | **Window dragging** (title-bar grab → `wm_move_clamped`) + **close button** (`wm_in_close_button` → `wm_destroy` → app exits) | v0.9.7 | ✅ live-confirmed in QEMU (`make demo-drag`/`make demo-close`) |
| 9.5.1 | **Damage-driven compositor**: off-screen back buffer (`wm_compose`) + per-event dirty-rect blits (`wm_window_bounds`); pointer moves no longer repaint the whole screen | v0.9.8 | ✅ live-confirmed in QEMU (pixel-identical to full repaint) |
| 9.6 | **Dock as a separate process** (`user/dock.c`): borderless `WM_F_DOCK` window, color-key transparency, `WM_POINTER` forwarding → hover + **click-to-launch** apps | v0.9.9 | ✅ live-confirmed in QEMU (`make demo-dock`) |
| 9.7 | **Finder** (`user/files.c`, `Aurora Files`): lists `/disk` via the `readdir` syscall, click-to-select, click-again-to-open (enter dir / exec `.ELF`) | v0.9.10 | ✅ live-confirmed in QEMU (`make demo-files`) |
| 9.8 | **Text Viewer** (`user/viewer.c`): `open`/`read`/`close` + 8×16 font, arrow/PgUp/PgDn scroll (keyboard now decodes extended scancodes) | v0.9.11 | ✅ live-confirmed in QEMU (`make demo-view`) |
| 9.9 | **Stabilization audit**: fix window-buffer leak (heap proven flat), free-on-full, dead-owner window reaping, destroy ownership check; verify zombies/limits/IPC | v1.0.0 | ✅ `make stress` + [docs/STABILITY.md](docs/STABILITY.md) |
| 10.1 | **Window controls**: minimize (window-shade) + maximize (resize protocol: `WM_RESIZE`, `WM_F_RESIZABLE`, server reallocs the surface; apps resize-aware) | v1.1.0 | ✅ live-confirmed (`make demo-max`/`make demo-min`) |
| 10.2 | **Aurora system menu** (in the windowserver): About / Settings / Close All Windows / Shut Down (`halt` syscall); launches apps via the menu | v1.1.1 | ✅ live-confirmed (`make demo-menu`) |
| 10.3 | **Settings**: Desktop pane (wallpaper + accent → `/disk/settings.cfg`, live `WM_RELOAD_SETTINGS`, persists) + System pane (`sysinfo`) | v1.1.2 | ✅ live-confirmed (`make demo-settings`) |
| 10.4 | Clipboard (`WM_CLIPBOARD_*`) — cross-process copy/paste | — | ⏳ NEXT (last of v1.1) |
| 8B | Ethernet/IP stack (virtio-net, ARP → IPv4 → UDP → TCP → DNS) **+ a full from-scratch TLS 1.3 / X.509 / HTTP(S) client, through HTTP/2** — this whole arc ran ahead of the desktop track and is tracked in detail in [docs/SECURITY.md](docs/SECURITY.md) (phases 11-17.5.2), not here | — | ✅ (HTTP/2 declared feature-complete, API frozen, as of 17.5.2) |
| 18.0 | **Kernel I/O & Scheduling (new track, opened once 17.5.2 closed the HTTP/2 arc): serial (COM1) RX** — `drivers/serial.c` gains an IRQ4 handler + ring buffer; `drivers/console.c` merges it with the keyboard so QEMU test scripts can type shell commands as raw bytes over a socket-backed serial chardev instead of scancode-injecting through the monitor's `sendkey` (slow, one key per `~0.12s`, a shift-key map needed per script). Found and fixed a real bug along the way: the first version polled both sources in a busy loop instead of blocking, leaving the reading thread `READY` and stealing scheduler time from other threads instead of stepping out of the run queue — fixed by giving both keyboard and serial IRQ handlers a shared `console_notify()` that wakes one blocked waiter, the same pattern the keyboard driver used alone before | — | ✅ `tools/qemu_serial.py`; `h2_reuse_qemu.py` migrated as proof (20/20 checks) |
| 18.1 | **Wait queues + sleep/wakeup**: `wait_queue_t` + `wait_event_timeout()` generalize the single-waiter block/wake pattern (keyboard, serial, pipes, sockets each rolled their own before); console/pipe/socket all migrated | — | ✅ |
| 18.2 | **Non-blocking I/O contract**: `O_NONBLOCK` + `EAGAIN`/`EWOULDBLOCK`, an `EINTR` contract defined (unused until Aurora has signals); console/pipe/socket honor it | — | ✅ |
| 18.3 | **Event waiting**: `wait_node_t` multi-queue primitive + `sys_wait_events()` (poll/select-style multi-fd wait) + libc wrapper | — | ✅ |
| 18.4 | **TCP sliding window + reassembly**: multiple segments in flight (`net/tcp.c` no longer tracks just one), out-of-order splicing, real receive-window management | — | ✅ |
| 18.5 | **Performance Characterization**: kernel-wide (`SYS_PROFSTAT`) and userspace (`httpsget --profile`) profiling counters, then a 10-scenario sweep (size/protocol/setup/reuse) against them. Verdict: AEAD is 0.026% of wall time at 5 MB — the prior "optimize ChaCha20-Poly1305 next" plan was wrong and is retired. Found and fixed a real busy-spin bug in `tcpsock_close()`'s teardown wait (145K pointless `net_poll()` calls per HTTP/2-style close, confirmed protocol-agnostic); then cleared the IRQ/driver path (`rx_irqs≈rx_packets`) and receive-window management (window closed 273µs total out of a 21.5s transfer) as explanations too. Every layer inside Aurora's client stack is now measured and cleared; the remaining ~4.6-5 KB/s ceiling sits outside the guest (QEMU `slirp` latency, or the Python test servers' own send pacing) — full trace in [docs/SECURITY.md](docs/SECURITY.md) "Step 18.5" | — | ✅ profile + one real fix; external validation ("Throughput under QEMU/slirp") tracked separately, not blocking |
| 10.1 | Aurora Assistant (userspace `aurorad`) + more desktop apps | — | ⏳ later |

## Verified behaviors

- Boots to an interactive shell from a FAT32 disk.
- Runs ELF programs in ring 3, each in its own address space.
- `argv` passing through `exec`; `malloc`/`free` and `printf` via the mini libc.
- Pipelines across processes: `cat /disk/poem.txt | grep aurora`.
- Background jobs (`cmd &`) started and auto-reaped.
- Message-passing IPC to a named service: shell `log <msg>` → `logger` daemon.
- Loopback sockets: `echosrv` binds port 7000 via `netd`; `echocli` connects,
  sends a line, and reads the echo back (client → netd → server → back).
- `poll()` on a connected socket (the echo server waits for data with it).
- uid foundation: services run as root (uid 0), the shell and its children run
  as uid 1000 (`id` shows it); `sock_link` is gated to root.
- VFS permissions: `/disk` files are root-owned `0755`; open/exec are
  permission-checked (uid 1000 can read+exec them but not write).
- Service permissions: `log`/`net` are public (`0644`); re-registering a name is
  owner/root-only (no service-name hijack).
- Privileged ports: binding a port < 1024 requires root (the echo demo uses
  7000); netd checks the requester's uid via `uid_of`.
- FS write: `save /disk/NOTE.TXT hello` creates/writes a FAT32 file, `cat`
  reads it back; files persist on the disk image. (Verified on the host with
  the real driver code + independent re-parse of the image.)
- Graphics: a static desktop (wallpaper + menu bar with labels + a clock + a
  Dock with lettered icons) renders via the 2D library and 8×16 font. Verified by
  rendering the real `kernel/gfx.c`+`desktop.c` to a PNG (`make screenshot` →
  `aurora_desktop.png`). Live paths (`make run-vbe`, `make iso`) await on-screen
  confirmation in QEMU.
- Window server (9.2): an event-driven userspace `windowserver` (single mailbox
  loop; only it writes the framebuffer; each PRESENT is a full recomposite) +
  interactive `Terminal`. Keyboard flows keyboard → windowserver (a forked
  reader child) → focused app → redraw. In graphics mode `init` runs the
  windowserver + Terminal (no text shell); in text mode it runs the shell as
  before. **Confirmed live in QEMU**: `make live-shot` captures the desktop +
  Terminal from the real framebuffer (`aurora_live.png`); `make verify-gui` types
  into the Terminal and captures the echoed text (`aurora_live_typed.png`,
  showing `aurora> hello aurora_`), proving the full keyboard→screen loop. The
  window-server core is also PNG-verified via `make screenshot-wm`.
- Mouse + cursor + click-to-focus (9.3): the kernel PS/2 mouse driver
  (`drivers/mouse.c`, IRQ12) buffers raw packets; the windowserver forks a second
  reader child that forwards `WM_MOUSE`. The cursor (an arrow drawn last, on top)
  tracks motion; a left-click hit-tests with `wm_window_at` and raises the window
  with `wm_raise`, moving focus so keys route there. **Confirmed live**: `make
  demo-focus` clicks the back Terminal, raises it, and types into it
  (`aurora_live_focus.png`). Text-mode boot is unaffected (mouse enabled but
  unused; keyboard verified).
- Window dragging + close button (9.4/9.5): the windowserver runs a small drag
  state machine in its `WM_MOUSE` handler. A left-press inside a title bar records
  the window + the cursor-to-origin offset; while the button is held each motion
  re-places the window via `wm_move_clamped` (clamped so a graspable strip always
  stays on-screen and the title bar never slides under the menu bar); release ends
  the drag. A press on the red title-bar button (`wm_in_close_button`) destroys the
  window (`wm_destroy`) and sends its owner a `WM_DESTROY` message so the app exits
  cleanly. **Confirmed live**: `make demo-drag` grabs the front Terminal's title
  bar and moves it (`aurora_live_drag.png`); `make demo-close` clicks its red button
  and the window disappears while its app logs `[term] window N closed`
  (`aurora_live_close.png`). `tools/verify_drag.py` pixel-asserts both.
- Dock as a separate process (9.6): `user/dock.c` is the first standalone GUI
  client — not part of `desktop.c`. It creates a **borderless** window (`WM_F_DOCK`)
  that the server pins bottom-center, keeps always on top, and excludes from
  keyboard focus; the panel's rounded corners use compositor color-key transparency
  so the desktop shows through. The server **forwards pointer events** to the window
  under the cursor (`WM_POINTER`, content-local coords); the Dock highlights the
  hovered icon and, on a left-click, **launches the app** (double-`fork`+`exec`, so
  it reparents to init). **Confirmed live**: `make demo-dock` clicks the Terminal
  icon and a new Terminal window appears (`aurora_live_dock.png`).
- Finder / Aurora Files (9.7): `user/files.c` lists a directory through the new
  `readdir` syscall — the VFS via ordinary syscalls, like the shell, with no
  special privileges. A single click selects a row (blue highlight); clicking the
  selected row opens it — a directory is entered (`..` goes up), an `.ELF` is
  exec'd (other files are handed to the Viewer, arriving in 9.8). Apps are spawned
  detached (double-`fork`+`exec`, reparented to init). **Confirmed live**: `make
  demo-files` opens the Finder from the Dock's Files icon, lists `/disk`, and
  double-clicks `TERM.ELF` to launch a Terminal (`aurora_live_files.png`).
- Text Viewer (9.8): `user/viewer.c` is launched by the Finder for non-`.ELF`
  files; it `open`/`read`/`close`s the file (capped at 64 KiB), splits it into
  lines (LF/CRLF) and renders them with the 8×16 font, scrolling with the arrow
  keys / PgUp/PgDn / j-k-space. This needed the keyboard driver to decode the
  `0xE0` extended scancodes (arrows, PgUp/PgDn, Home/End) into shared `KEY_*`
  codes (`include/keys.h`) that flow through the existing char pipeline →
  `WM_KEY`. **Confirmed live**: `make demo-view` opens the Finder, double-clicks
  `ABOUT.TXT`, and the Viewer shows it scrolled by PgDn (`aurora_live_view.png`).
- Settings (10.3, v1.1.2): the Settings app (launched from the Aurora menu) has a
  Desktop pane that sets the wallpaper + accent color and a read-only System pane.
  Choices are written to `/disk/settings.cfg` as plain `key=value` lines (just the
  VFS — `open`/`write`/`close`, no new IPC); the windowserver re-reads them on a
  `WM_RELOAD_SETTINGS` message and at boot, so the desktop re-themes live and the
  choice survives a reboot. The System pane reads RAM / free pages / process count
  / uptime via the new `sysinfo` syscall. **Confirmed live**: `make demo-settings`
  switches to the Aurora Dark wallpaper + Orange accent (`aurora_live_settings.png`);
  a fresh boot loads the saved theme.
- Aurora system menu (10.2, v1.1.1): the menu bar's "Aurora" title opens a
  windowserver-drawn dropdown. **About AuroraOS** launches the Viewer on
  `/disk/ABOUT.TXT`; **Settings...** launches the `settings` placeholder app
  (both via a double-`fork`+`exec` from the windowserver); **Close All Windows**
  destroys every window but the Dock (apps get `WM_DESTROY` and exit);
  **Shut Down** paints "It is now safe to power off AuroraOS." and calls the new
  root-only `halt` syscall (ACPI poweroff + CPU halt). The menu lives in the
  windowserver (chrome), so it works even with no Dock. **Confirmed live**: `make
  demo-menu` (`aurora_live_menu.png`), plus About/Settings/Close/Shut Down each
  verified (`aurora_live_shutdown.png`).
- Window controls (10.1, v1.1.0): the title-bar traffic lights are live — red
  closes (9.5), **yellow window-shades** (collapse to/expand from the title bar),
  **green maximizes/restores**. Maximize uses a resize protocol: a window opts in
  with `WM_F_RESIZABLE`; on the green click the server reallocs the content surface
  to fill the screen and sends the app `WM_RESIZE {w,h}`, and the app (Terminal,
  Finder, Viewer) recomputes its layout and redraws. **Confirmed live**: `make
  demo-max` fills the screen with a Terminal (`aurora_live_max.png`); `make
  demo-min` collapses one to its title bar (`aurora_live_min.png`).
- Stabilization (v1.0.0): `make stress` (`user/wmstress.c`, launched from the
  Dock's diagnostics icon) hammers the window server — 2×50 create/destroy cycles
  leave the server heap top (`brk`) **identical** between rounds (no leak), and a
  24-window burst fills the table to `WM_MAX_WINDOWS` with the overflow failing
  gracefully (no crash). Closing the Finder logs `[init] reaped adopted child`
  (no zombie) and it relaunches cleanly from the Dock. See
  [docs/STABILITY.md](docs/STABILITY.md).
- Orphan reparenting to init and reaping (`orphan`).
- Graceful shutdown: init asks the logger to stop, force-kills survivors
  (netd), and reaps everything.
- Clean teardown: address spaces, kernel stacks, PCBs reclaimed.
- Serial command channel (18.0): COM1 RX (IRQ4) feeds the same console input
  stream as the keyboard, so a QEMU test can connect to a socket-backed serial
  chardev and type a shell command as raw bytes — no scancode injection, no
  shift-key map, no per-character delay. Verified live (a raw socket sending
  `id\n`/`help\n` got back exactly the expected shell output) and via
  `tools/h2_reuse_qemu.py` migrated to the new channel, still 20/20 checks.

> Phases 0–7 behaviors were exercised interactively in QEMU. The Phase 8A
> behaviors above are verified by clean cross-builds and a host-side simulation
> of the socket data path; the interactive QEMU boot test is pending.

## Component inventory

- **arch/i386:** boot.S, gdt(+TSS), idt, isr/interrupt, pmm, paging, switch,
  usermode, io.
- **drivers:** vga, serial, keyboard, pit, ata, console, fb, mouse.
- **fs:** vfs, tmpfs, fat32.
- **lib (kernel):** string, printf (kprintf), kheap.
- **kernel:** kmain, scheduler, process, pipe, socket, elf, syscall, gfx, desktop.
- **user:** crt0, libc (libc.h + string/printf/malloc/net), wm (compositor core),
  init, logger, netd, sh, cat, grep, hello, orphan, echosrv, echocli, save,
  wserver (windowserver), term (Terminal app), dock (Dock app),
  files (Finder / Aurora Files), viewer (Text Viewer), settings (control panel),
  wmstress (WS self-test).
- **tools:** bin2c.py, mkfat32.py, render_desktop.c, render_wm.c, ppm2png.py,
  genfont.py, screendump.py (headless live-framebuffer capture via QEMU monitor),
  verify_drag.py (pixel-asserts window drag + close).
- **docs:** ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC, NETWORKING, GRAPHICS, INPUT, STABILITY.

## Syscalls (31)

`putc, yield, exit, fork, exec, wait, open, read, write, close, getpid, pipe,
dup2, sbrk, msgsend, msgrecv, register, lookup, kill, socket, sock_link, poll,
getuid, setuid, uid_of, fb_map, fb_active, mouse, readdir, halt, sysinfo`. See
[docs/SYSCALLS.md](docs/SYSCALLS.md).
