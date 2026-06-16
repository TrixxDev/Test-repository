# AuroraOS — Current Status

Phase-by-phase status of the project. Forward plan: [NEXT_STEPS.md](NEXT_STEPS.md).
Caveats: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

**Current version: v0.9.10.** Phases 0–7 are implemented and verified by booting
in QEMU (interactive parts driven via PS/2 input). Phase 8A (loopback sockets +
netd + poll), Phase 8A.5 (security), FS write (FAT32 read/write) and graphics
(framebuffer + 2D library with an 8×16 font + desktop; a userspace, event-driven
**windowserver** with a keyboard input pipeline + interactive Terminal) are
implemented and build clean. **Phases 9.2–9.7 are confirmed live in QEMU**:
the Bochs-VBE framebuffer comes up, the windowserver paints the desktop, Terminal
windows open, typing flows keyboard → windowserver → focused app → on-screen
redraw, the **PS/2 mouse** moves an on-screen cursor + **clicks to focus**
(click a window to raise it; keys then route to it), a window can be
**dragged by its title bar** and **closed with the red title-bar button**, the
**Dock is its own process** — a borderless, always-on-top GUI client that draws
its icons, highlights on hover, and **launches apps on click** — and the
**Finder (`Aurora Files`) browses the filesystem**: it lists `/disk` via the new
`readdir` syscall (the VFS, used through ordinary syscalls like the shell — no
special privileges), selects a row on click, and on a second click **opens** it
(a directory is entered, an `.ELF` is exec'd). All captured to PNG via
`make verify-gui` / `make demo-focus` / `make demo-drag` / `make demo-close` /
`make demo-dock` / `make demo-files` (drag + close pixel-asserted by
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
| 9.8 | Text Viewer (`Viewer.app`) — open `POEM.TXT` from the Finder | — | ⏳ NEXT |
| 8B | Ethernet/IP stack (virtio-net, ARP → IPv4 → UDP → TCP → DNS) | — | ⏳ after desktop |
| 10 | Desktop apps + Aurora Assistant (userspace `aurorad`) | — | ⏳ later |

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
- Orphan reparenting to init and reaping (`orphan`).
- Graceful shutdown: init asks the logger to stop, force-kills survivors
  (netd), and reaps everything.
- Clean teardown: address spaces, kernel stacks, PCBs reclaimed.

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
  files (Finder / Aurora Files).
- **tools:** bin2c.py, mkfat32.py, render_desktop.c, render_wm.c, ppm2png.py,
  genfont.py, screendump.py (headless live-framebuffer capture via QEMU monitor),
  verify_drag.py (pixel-asserts window drag + close).
- **docs:** ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC, NETWORKING, GRAPHICS, INPUT.

## Syscalls (29)

`putc, yield, exit, fork, exec, wait, open, read, write, close, getpid, pipe,
dup2, sbrk, msgsend, msgrecv, register, lookup, kill, socket, sock_link, poll,
getuid, setuid, uid_of, fb_map, fb_active, mouse, readdir`. See
[docs/SYSCALLS.md](docs/SYSCALLS.md).
