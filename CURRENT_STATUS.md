# AuroraOS — Current Status

Phase-by-phase status of the project. Forward plan: [NEXT_STEPS.md](NEXT_STEPS.md).
Caveats: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

**Current version: v0.9.1.** Phases 0–7 are implemented and verified by booting
in QEMU (interactive parts driven via PS/2 input). Phase 8A (loopback sockets +
netd + poll), Phase 8A.5 (security), FS write (FAT32 read/write) and graphics
(Phase 9.0 framebuffer + minimal 9.1 2D library with an 8×16 font + a static
desktop, plus two live-output paths) are implemented and build clean. FS write
and the desktop rendering are verified on the host (the real `fs/fat32.c` write
path + image re-parse; the real `kernel/gfx.c`+`kernel/desktop.c` rendered to a
PNG). The live framebuffer (`make run-vbe` / `make iso`) needs an interactive
QEMU run to confirm on screen — pending (no QEMU in the current CI sandbox).

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
| 9.0.5 | Live output: 8×16 text/font; Bochs-VBE fallback (`run-vbe`) + GRUB ISO (`iso`) | v0.9.1 | ✅ (needs on-screen confirm) |
| 9.2 | Window server + compositor (userspace), PS/2 mouse | — | ⏳ **next** |
| 9.3+ | Desktop, windows, Finder, design system (fonts/alpha/shadows) | — | ⏳ later |
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
- **drivers:** vga, serial, keyboard, pit, ata, console.
- **fs:** vfs, tmpfs, fat32.
- **lib (kernel):** string, printf (kprintf), kheap.
- **kernel:** kmain, scheduler, process, pipe, socket, elf, syscall.
- **user:** crt0, libc (libc.h + string/printf/malloc/net), init, logger, netd,
  sh, cat, grep, hello, orphan, echosrv, echocli.
- **tools:** bin2c.py, mkfat32.py.
- **docs:** ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC, NETWORKING.

## Syscalls (26)

`putc, yield, exit, fork, exec, wait, open, read, write, close, getpid, pipe,
dup2, sbrk, msgsend, msgrecv, register, lookup, kill, socket, sock_link, poll,
getuid, setuid, uid_of`. See [docs/SYSCALLS.md](docs/SYSCALLS.md).
