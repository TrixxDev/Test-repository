# AuroraOS — Architecture

This is the system-level overview. Detailed contracts live in [`docs/`](docs/):
[ABI](docs/ABI.md), [SYSCALLS](docs/SYSCALLS.md),
[PROCESS_MODEL](docs/PROCESS_MODEL.md), [VFS](docs/VFS.md), [IPC](docs/IPC.md).

## Design principles

1. **Monolithic kernel, microkernel-style userland.** The kernel owns
   scheduling, memory, drivers, and IPC. Everything else (init, logger, shell,
   future netd / window server / aurorad) is an ordinary userspace process
   reachable via IPC and the service registry.
2. **Stable ABI first.** Syscall numbers live in one shared header
   (`include/syscall_abi.h`) used by both kernel and userland. Append-only.
3. **Composability.** Pipes + fork/exec give Unix-style program composition;
   message passing + a name registry give service-style communication.
4. **Verify in the real machine.** Every phase is booted in QEMU and exercised
   (including interactive shell sessions via PS/2 input).

## Layered structure

```
                      ring 3 (userland)
  init ─ logger ─ netd ─ sh ─ cat/grep/hello/orphan/echosrv/echocli   processes
   │       │       │     │
   └─ IPC (pipes, messages, name registry) + sockets (socket/poll) ───┐
                                                        │  int 0x80
====================== ring 0 (kernel) =================│=========
  syscall dispatch                                      ▼
  ├─ process model (PCB, uid, fork/exec/wait, fds, mailbox)
  ├─ scheduler (threads, states, context switch)
  ├─ memory (PMM, paging, per-proc address space, kheap)
  ├─ socket layer (struct socket endpoints, sock_link, poll) — mechanism only
  ├─ VFS ── tmpfs / FAT32 / console
  ├─ drivers (ata, keyboard, pit, serial, vga)
  └─ arch (GDT/TSS, IDT, ISR/IRQ, PIC)
                          │
                       hardware (QEMU i686)
```

The networking "stack" is deliberately **not** in the kernel: the kernel only
provides socket endpoints + a privileged `sock_link`, and the `netd` daemon owns
ports and the bind/connect/accept rendezvous. See
[docs/NETWORKING.md](docs/NETWORKING.md).

## Boot flow

1. `qemu -kernel` finds the Multiboot1 header in `.multiboot` and enters
   `_start` (`arch/i386/boot.S`) in 32-bit protected mode.
2. `_start` sets up a stack and calls `kernel_main` (`kernel/kmain.c`) with the
   Multiboot magic + info pointer.
3. `kernel_main` brings up: serial + VGA → GDT/TSS → IDT → ISR/IRQ + PIC +
   syscalls → PIT (100 Hz) → keyboard → PMM (from E820) → paging → kernel heap
   → VFS (tmpfs, FAT32 over ATA) → scheduler + process model.
4. It spawns **init** from `/disk/INIT.ELF` (fallback: embedded copy in tmpfs),
   adds an idle thread, enables scheduling, and `wait`s to reap init.

## Memory model

- **Physical:** bitmap frame allocator (`arch/i386/pmm.c`), 4 KiB frames, sized
  from the Multiboot/E820 map.
- **Virtual:** two-level paging with **recursive mapping** (PD entry 1023). The
  low 16 MiB is identity-mapped; the kernel also lives in high memory
  (≥ `0xC0000000`).
- **Per-process address spaces:** each process has its own page directory; the
  kernel mappings (low identity + high half) are shared by reference. Switching
  threads reloads `CR3` only when the address space changes.
- **Kernel heap:** `kmalloc`/`kfree` (`lib/kheap.c`) over on-demand mapped
  pages.
- **User heap:** `sbrk` grows a per-process region at `0x50000000`; the user
  `malloc` (mini libc) is built on it.

Layout per process: kernel low identity (0–16 MiB) · program at `0x40000000` ·
heap at `0x50000000` · stack top at `0xC0000000` · kernel high half above.
See [docs/ABI.md](docs/ABI.md).

## Process & thread model

- **Process = address space + fd table + IPC mailbox + state + a thread**
  (`kernel/process.h`). One thread per process today; structures allow more.
- **Scheduler** (`kernel/scheduler.c`): preemptive round-robin over a circular
  thread list, driven by the PIT tick. Run states READY / BLOCKED / ZOMBIE.
  An always-runnable **idle thread** lets the CPU `hlt` with interrupts on so
  IRQs can wake blocked threads.
- **Context switch** (`switch.S`) saves/restores callee-saved registers; the
  scheduler also updates `CR3` and `TSS.esp0`.
- **Lifecycle:** `fork` (copies the address space, no COW), `exec` (replaces
  the image, sets up `argc`/`argv`), `wait`/`exit` with exit codes, orphan
  reparenting to init, zombie reaping, `kill`, graceful shutdown.
  See [docs/PROCESS_MODEL.md](docs/PROCESS_MODEL.md).

## System call interface

`int 0x80`; `eax` = number, `ebx`/`ecx`/`edx` = args, `eax` = return. 26 calls:
process control, fds, pipes/dup2, sbrk, message-passing IPC, the name registry,
loopback sockets (`socket`/`sock_link`/`poll`), and uid
(`getuid`/`setuid`/`uid_of`). Full table in [docs/SYSCALLS.md](docs/SYSCALLS.md).

## Filesystem

VFS (`fs/vfs.c`) abstracts concrete filesystems behind `vfs_node_t` + an ops
table, attached at mount points:

- **tmpfs** (`/tmp`) — in-memory, read/write/create.
- **FAT32** (`/disk`) — read-only, over the ATA PIO driver; reads the disk image
  built by `tools/mkfat32.py`.
- **console** — a device node backing stdin/stdout/stderr.

File descriptors live in the PCB (`open/read/write/close`, inherited across
fork, refcounted). See [docs/VFS.md](docs/VFS.md).

## IPC

Two mechanisms (see [docs/IPC.md](docs/IPC.md)):

- **Pipes** — byte streams (`pipe`/`dup2`/`close`) with a blocking ring buffer
  and read/write-end refcounts; the shell uses them for `a | b`.
- **Message passing** — per-process mailboxes (`msgsend`/`msgrecv`) plus a
  **named service registry** (`register`/`lookup`) so clients find services by
  name. This is the foundation for the daemons (logger, netd) and future ones
  (window server, aurorad).

## Sockets & networking (Phase 8A)

Loopback (`AF_LOOPBACK`) stream sockets, built as a userspace service over IPC.
The kernel's socket layer is **mechanism only** — `struct socket` endpoints
backed by fds, joined by the root-only `sock_link`, with `poll` for readiness;
`send`/`recv` are just `write`/`read`. The `netd` daemon is the **stack**: it
owns ports and the bind/connect/accept rendezvous, then asks the kernel to link
the two endpoints, after which data flows endpoint-to-endpoint. Verified end to
end by `echosrv`/`echocli`. Full design in [docs/NETWORKING.md](docs/NETWORKING.md).

## Security (foundation, Phase 8A.5)

A deliberately-placed security model, added *before* the network grows the
attack surface:

- **uid** — each process carries a `uid` (`kernel/process.h`), inherited across
  `fork`/`exec`/spawn. Kernel + services (init, logger, netd) are root (uid 0);
  the shell and everything it launches are uid 1000. `setuid` only drops
  privilege; `uid_of(pid)` lets a daemon learn a peer's uid from the kernel.
- **VFS rwx** — nodes have `owner_uid` + Unix-style `mode`; `open` checks R/W
  and `exec` checks X (root bypasses). `/disk` is root-owned `0755`.
- **Service registry** — services have an owner + mode; "read" gates `lookup`,
  and a name can only be re-registered by its owner or root (no hijack).
- **Privileged ports** — netd refuses to `bind` a port < 1024 for non-root,
  using `uid_of` so the requester can't forge its uid.

See [docs/VFS.md](docs/VFS.md), [docs/IPC.md](docs/IPC.md),
[docs/NETWORKING.md](docs/NETWORKING.md). Login, groups, and per-FS persisted
permissions are future work ([NEXT_STEPS.md](NEXT_STEPS.md)).

## Userland & build pipeline

- User programs are freestanding ELF32 binaries linked against `crt0.S` and the
  mini libc (`user/libc.h`, `user/libc/`).
- The build (`Makefile`) compiles user programs separately, embeds `init` into
  the kernel as a fallback (`tools/bin2c.py`), and writes all programs + a
  sample text file into a FAT32 image (`tools/mkfat32.py`) attached to QEMU.
