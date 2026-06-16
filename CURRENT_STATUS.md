# AuroraOS — Current Status

Phase-by-phase status of the project. Forward plan: [NEXT_STEPS.md](NEXT_STEPS.md).
Caveats: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

**Current version: v0.9.5.** Phases 0–7 are implemented and verified by booting
in QEMU (interactive parts driven via PS/2 input). Phase 8A (loopback sockets +
netd + poll), Phase 8A.5 (security), FS write (FAT32 read/write) and graphics
(framebuffer + 2D library with an 8×16 font + desktop; a userspace, event-driven
**windowserver** with a keyboard input pipeline + interactive Terminal) are
implemented and build clean. **Phase 9.2 is now confirmed live in QEMU**: the
Bochs-VBE framebuffer comes up, the windowserver paints the desktop, the Terminal
window opens, and typing flows keyboard → windowserver → focused app → on-screen
redraw — captured to PNG via `make verify-gui` (see `aurora_live.png`). FS write
and the rendering/window-server core are additionally verified on the host (the
real `fs/fat32.c` write path + image re-parse; the real
`kernel/gfx.c`/`desktop.c`/`wm.c` rendered to PNGs).

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
| 9.3–9.7 | Mouse + cursor → click-to-focus → window dragging → Dock process → Launcher/Finder (design in docs/INPUT.md) | — | ⏳ NEXT (9.2 gate is green) |
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
- **drivers:** vga, serial, keyboard, pit, ata, console, fb.
- **fs:** vfs, tmpfs, fat32.
- **lib (kernel):** string, printf (kprintf), kheap.
- **kernel:** kmain, scheduler, process, pipe, socket, elf, syscall, gfx, desktop.
- **user:** crt0, libc (libc.h + string/printf/malloc/net), wm (compositor core),
  init, logger, netd, sh, cat, grep, hello, orphan, echosrv, echocli, save,
  wserver (windowserver), term (Terminal app).
- **tools:** bin2c.py, mkfat32.py, render_desktop.c, render_wm.c, ppm2png.py,
  genfont.py, screendump.py (headless live-framebuffer capture via QEMU monitor).
- **docs:** ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC, NETWORKING, GRAPHICS, INPUT.

## Syscalls (27)

`putc, yield, exit, fork, exec, wait, open, read, write, close, getpid, pipe,
dup2, sbrk, msgsend, msgrecv, register, lookup, kill, socket, sock_link, poll,
getuid, setuid, uid_of, fb_map, fb_active`. See [docs/SYSCALLS.md](docs/SYSCALLS.md).
