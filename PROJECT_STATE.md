# AuroraOS — Project State

A snapshot of what AuroraOS is and what currently exists. For deeper detail see
[ARCHITECTURE.md](ARCHITECTURE.md), the technical specs in [`docs/`](docs/), and
the forward plan in [NEXT_STEPS.md](NEXT_STEPS.md).

## What it is

AuroraOS is a from-scratch, 32-bit (i686) operating system: a monolithic kernel
with a Unix-like userland. It boots in QEMU, runs ELF programs in ring 3, has a
filesystem stack, an interactive shell, pipes, a small libc, and a userspace
service model (init + daemons + message-passing IPC).

It has moved well past a "teaching kernel" — it is an early Unix-like execution
environment. It is **not** yet a daily-driver OS (no networking, no GUI, no FS
writes to disk, no multi-user/security model).

- **Current version:** v0.7.1
- **Size:** ~4,700 lines of C / assembly across kernel + drivers + fs + libc +
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
| Ring 3 | ✅ | User mode via TSS + `iret`, `int 0x80` syscalls (19 calls). |
| Filesystem | ✅ | VFS (mounts, vnodes, ops); tmpfs (rw); FAT32 (read-only) over ATA; console device. |
| Executables | ✅ | ELF32 loader (PT_LOAD), `argc`/`argv` setup, crt0. |
| IPC | ✅ | Pipes (`pipe`/`dup2`), message passing (`msgsend`/`msgrecv`), named service registry. |
| Userland | ✅ | mini libc; `init`, `logger`, `sh`, `cat`, `grep`, `hello`, `orphan`. |
| Networking | ❌ | Not started (next major phase). |
| Graphics | ❌ | Text mode only. |
| Security / multi-user | ❌ | Single-user, no permissions. |

## What you can do today

Boot and get an interactive shell that composes real programs:

```
aurora> hello one two            # argv + malloc demo
aurora> cat /disk/poem.txt | grep aurora   # pipes between two processes
aurora> log system online        # IPC message to the logger daemon
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
kernel/      kmain, scheduler, process, pipe, elf, syscall
include/     kio.h, multiboot.h, syscall_abi.h (shared ABI), syscall.h
user/        crt0, libc (libc.h + libc/), programs (init, logger, sh, cat, grep, hello, orphan)
tools/       bin2c.py (embed ELF), mkfat32.py (build FAT32 image)
docs/        ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC
linker.ld    kernel link map (load at 1 MiB)
Makefile     clang/lld cross-build + user programs + disk image
```

> `index.php` is a leftover from the original empty repository and is unrelated
> to the OS.

## Version history

See [CURRENT_STATUS.md](CURRENT_STATUS.md) for the phase-by-phase table.
