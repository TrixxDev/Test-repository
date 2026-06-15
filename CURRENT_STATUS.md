# AuroraOS — Current Status

Phase-by-phase status of the project. Forward plan: [NEXT_STEPS.md](NEXT_STEPS.md).
Caveats: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

**Current version: v0.7.1.** All phases below are implemented and verified by
booting in QEMU (interactive parts driven via PS/2 input).

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
| 8 | Networking (loopback → netd → stack) | — | ⏳ next |
| 9 | Graphics (window server → compositor → framebuffer) | — | ⏳ later |
| 10 | Desktop + Aurora Assistant (userspace `aurorad`) | — | ⏳ later |

## Verified behaviors

- Boots to an interactive shell from a FAT32 disk.
- Runs ELF programs in ring 3, each in its own address space.
- `argv` passing through `exec`; `malloc`/`free` and `printf` via the mini libc.
- Pipelines across processes: `cat /disk/poem.txt | grep aurora`.
- Background jobs (`cmd &`) started and auto-reaped.
- Message-passing IPC to a named service: shell `log <msg>` → `logger` daemon.
- Orphan reparenting to init and reaping (`orphan`).
- Graceful shutdown: init asks the logger to stop, waits, force-kills as
  fallback.
- Clean teardown: address spaces, kernel stacks, PCBs reclaimed.

## Component inventory

- **arch/i386:** boot.S, gdt(+TSS), idt, isr/interrupt, pmm, paging, switch,
  usermode, io.
- **drivers:** vga, serial, keyboard, pit, ata, console.
- **fs:** vfs, tmpfs, fat32.
- **lib (kernel):** string, printf (kprintf), kheap.
- **kernel:** kmain, scheduler, process, pipe, elf, syscall.
- **user:** crt0, libc (libc.h + string/printf/malloc), init, logger, sh, cat,
  grep, hello, orphan.
- **tools:** bin2c.py, mkfat32.py.
- **docs:** ABI, SYSCALLS, PROCESS_MODEL, VFS, IPC.

## Syscalls (19)

`putc, yield, exit, fork, exec, wait, open, read, write, close, getpid, pipe,
dup2, sbrk, msgsend, msgrecv, register, lookup, kill`. See
[docs/SYSCALLS.md](docs/SYSCALLS.md).
