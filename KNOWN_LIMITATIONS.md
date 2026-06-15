# AuroraOS — Known Limitations

An honest list of what is missing, simplified, or fragile as of **v0.7.1**.
These are deliberate trade-offs for an early-stage system, tracked so they are
fixed before they become load-bearing. See [NEXT_STEPS.md](NEXT_STEPS.md).

## Major missing subsystems

- **Networking:** none yet (next phase). No sockets, no loopback, no stack.
- **Graphics:** text mode (VGA 80×25) only. No framebuffer, compositor, or GUI.
- **Filesystem writes to disk:** FAT32 is **read-only**. Persistent writes,
  block cache, and a writable on-disk FS are not implemented (tmpfs is RAM-only).
- **Multi-user / security:** single user, no permissions, ownership, or
  isolation beyond per-process address spaces. Syscalls trust user pointers
  (no `copy_from_user` validation) — a bad pointer can fault the kernel.
- **Signals:** no real signals; "shutdown" is an IPC message by convention.

## Memory & process model

- **fork is not copy-on-write:** every user page is copied eagerly. Correct but
  memory- and time-expensive for large processes.
- **One thread per process:** the structures allow more, but threads-per-process
  and thread APIs are not implemented.
- **No demand paging / swap:** all mapped pages are backed immediately; no
  page-out, no memory pressure handling.
- **Fixed limits:** `MAX_PROCS=32`, `MAX_FDS=16`, `MAX_SERVICES=16`, mailbox
  cap `MBOX_LIMIT=64`, message size `MSG_MAX=256`. No dynamic growth.
- **`kill` of a kernel-blocked process is coarse:** it frees the target's
  resources directly. Fine for the cooperative graceful-shutdown path; not a
  general preemptive-kill-anything primitive.
- **Daemon supervision is minimal:** init restarts a died logger and reaps
  orphans, but there are no restart policies, backoff, or health checks.
- **Address-space limits:** user code is assumed at `0x40000000`, heap at
  `0x50000000`, stack top `0xC0000000`; large/unusual ELF layouts aren't handled.

## Filesystem & storage

- **FAT32 read-only**, 8.3 names only (no long file names), no subdirectory
  creation, no timestamps/attributes beyond what's read.
- **VFS** has no path normalization (`.`/`..`), no symlinks, no permissions.
- **ATA driver** is PIO, primary master only, LBA28, no DMA, no error recovery
  beyond basic status polling.
- **mkfat32.py** builds a fixed 16 MiB image with specific BPB parameters; it is
  a build helper, not a general FAT tool.

## Userland & libc

- **mini libc** is intentionally tiny: `printf`/`fprintf` cover a subset of
  formats (`%d %u %x %c %s %%`, no width/precision); `malloc` is first-fit with
  no block splitting/coalescing on free; limited string/stdio coverage.
- **Shell** supports a **single** pipe (`a | b`), a trailing `&`, and a few
  builtins; no `a | b | c`, no redirects, no quoting/globbing, no job control.
- **No environment variables**, no working directory concept, no argv quoting.

## Drivers & platform

- **i686 / single CPU only.** No SMP, no APIC (legacy PIC), no ACPI.
- **Timer** is a fixed 100 Hz tick; no high-resolution timers or proper sleep.
- **Keyboard** is US scancode set 1, basic shift handling, single input
  waiter; no full keymap, no caps lock, limited line editing (backspace only).
- **No real-time clock**, no power management, no PCI enumeration.

## Build, boot & testing

- **Boots only via `qemu -kernel`** (Multiboot1). No GRUB ISO / real-hardware
  boot path tested; no bootable disk image.
- **No automated test suite.** Verification is manual: boot in QEMU and exercise
  behaviors (interactive parts driven via the QEMU monitor `sendkey`).
- **Toolchain-specific:** built with `clang`/`ld.lld`; relies on Python for the
  embedded blob and FAT32 image.

## Misc

- `index.php` at the repo root is leftover from the original empty repository
  and is unrelated to the OS.
- Some forced-termination and orphan paths after `init` exits rely on the
  scheduler being disabled at shutdown; they are not a general teardown of a
  live multi-service system.

## Reliability notes

These are not user-facing daily-OS concerns yet, but matter as the system
grows: trusting user pointers in syscalls, fixed-size kernel stacks (8 KiB) with
some stack-heavy routines (e.g. address-space teardown), and eager fork copying
are the most likely sources of future bugs under heavier workloads.
