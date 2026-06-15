# AuroraOS — Project State

A snapshot of what AuroraOS is and what currently exists. For deeper detail see
[ARCHITECTURE.md](ARCHITECTURE.md), the technical specs in [`docs/`](docs/), and
the forward plan in [NEXT_STEPS.md](NEXT_STEPS.md).

## What it is

AuroraOS is a from-scratch, 32-bit (i686) operating system: a monolithic kernel
with a Unix-like userland. It boots in QEMU, runs ELF programs in ring 3, has a
filesystem stack, an interactive shell, pipes, a small libc, a userspace
service model (init + daemons + message-passing IPC), and loopback sockets
brokered by a userspace network daemon.

It has moved well past a "teaching kernel" — it is an early Unix-like execution
environment that is starting to look like a platform of services, and now has the
first piece of its macOS-like visual stack (a linear framebuffer, a 2D library,
and a static desktop with a menu bar and Dock). It is **not** yet a daily-driver
OS (no external networking yet — loopback only; the GUI is a static desktop, no
window server yet; a basic permission model — uid + rwx — but no login/groups).

- **Current version:** v0.9.0
- **Size:** ~6,200 lines of C / assembly across kernel + drivers + fs + libc +
  userland.
- **Target:** i686 protected mode, Multiboot1, booted directly by
  `qemu-system-i386 -kernel`.
- **Toolchain:** `clang` as a cross-compiler (no separate cross-gcc), `ld.lld`,
  Python helpers for the embedded blob and the FAT32 image. No `nasm`/`grub`
  required.

## Implemented, by layer

| Layer | Status | Highlights |
|-------|--------|-----------|
| Boot | ✅ | Multiboot1 header, `_start`, stack, jump to C. |
| CPU/arch | ✅ | GDT + TSS, IDT, ISR/IRQ stubs, PIC remap. |
| Drivers | ✅ | VGA text console, COM1 serial, PS/2 keyboard, PIT timer, ATA PIO disk. |
| Memory | ✅ | E820 parse, bitmap PMM, paging (recursive), per-process address spaces, kernel heap, `sbrk`. |
| Scheduling | ✅ | Preemptive round-robin threads, run states, block/wake, idle thread, context switch. |
| Processes | ✅ | PCB, `fork`/`exec`/`wait`/`exit`, exit codes, reparent-to-init, zombie reaping, `kill`. |
| Ring 3 | ✅ | User mode via TSS + `iret`, `int 0x80` syscalls (26 calls). |
| Filesystem | ✅ | VFS (mounts, vnodes, ops, rwx/owner); tmpfs (rw); FAT32 **read/write** over ATA (create/grow/truncate); console device. |
| Executables | ✅ | ELF32 loader (PT_LOAD), `argc`/`argv` setup, crt0. |
| IPC | ✅ | Pipes (`pipe`/`dup2`), message passing (`msgsend`/`msgrecv`), named service registry. |
| Sockets / poll | ✅ (8A) | Kernel `struct socket` (AF_LOOPBACK), `socket`/`poll`; `netd` brokers bind/connect/accept over IPC; `sock_link` joins endpoints. |
| Userland | ✅ | mini libc; `init`, `logger`, `netd`, `sh`, `cat`, `grep`, `hello`, `orphan`, `echosrv`, `echocli`. |
| Networking (NIC/IP) | ⏳ | Loopback done (8A); Ethernet/ARP/IP/UDP/TCP is 8B. |
| Graphics | 🟡 (9.0/9.1) | Linear framebuffer (Multiboot); 2D library (rects, rounded rects, circles, gradient, blit); static desktop (wallpaper + menu bar + Dock). No window server/fonts yet. |
| Security / multi-user | 🟡 (8A.5) | uid (root vs user, `getuid`/`setuid`/`uid_of`); rwx + owner on VFS nodes enforced at open/exec; service registry permissions; privileged ports (<1024) root-only. No login/groups yet. |

## What it looks like

The first AuroraOS desktop (rendered by the real `kernel/gfx.c` +
`kernel/desktop.c`; run `make screenshot` to regenerate):

![AuroraOS desktop](aurora_desktop.png)

## What you can do today

Boot and get an interactive shell that composes real programs:

```
aurora> hello one two            # argv + malloc demo
aurora> cat /disk/poem.txt | grep aurora   # pipes between two processes
aurora> log system online        # IPC message to the logger daemon
aurora> id                       # shows uid=1000 (the shell runs unprivileged)
aurora> echosrv &                # loopback echo server (binds port 7000 via netd)
aurora> echocli hello-loopback   # client -> netd -> server -> back
aurora> save /disk/NOTE.TXT hi   # write a file to disk (FAT32 write)
aurora> cat /disk/NOTE.TXT       # read it back (persists across reboot)
aurora> orphan                   # orphan reparented to init and reaped
aurora> hello job &              # background job, auto-reaped
aurora> exit                     # graceful shutdown of services
```

## Build & run

```sh
make          # builds aurora.elf + disk.img (kernel, user programs, FAT32 image)
make run      # boots in QEMU with the disk attached (serial log on stdio)
make debug    # same, waits for GDB on :1234
make clean
```

Interactive input in headless QEMU can be driven via the monitor `sendkey`
command (see the session history / NEXT_STEPS for how tests are run).

## Repository map

```
arch/i386/   CPU/arch: boot, GDT/TSS, IDT, ISR, PMM, paging, context switch, ring3
drivers/     vga, serial, keyboard, pit, ata, console
fs/          vfs, tmpfs, fat32
lib/         freestanding kernel lib: string, printf (kprintf), kheap
kernel/      kmain, scheduler, process, pipe, socket, elf, syscall, gfx, desktop
drivers/     vga, serial, keyboard, pit, ata, console, fb (framebuffer)
include/     kio.h, multiboot.h, syscall_abi.h (shared ABI), syscall.h, net.h (netd protocol)
user/        crt0, libc (libc.h + libc/), programs (init, logger, netd, sh, cat,
             grep, hello, orphan, echosrv, echocli, save)
tools/       bin2c.py (embed ELF), mkfat32.py (FAT32 image), render_desktop.c +
             ppm2png.py (host desktop -> PNG)
docs/        ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC, NETWORKING, GRAPHICS
linker.ld    kernel link map (load at 1 MiB)
Makefile     clang/lld cross-build + user programs + disk image
```

> `index.php` is a leftover from the original empty repository and is unrelated
> to the OS.

## Version history

See [CURRENT_STATUS.md](CURRENT_STATUS.md) for the phase-by-phase table.
