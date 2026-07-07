# AuroraOS ABI

This document fixes the application binary interface. Once a userspace program
is built against it, the kernel must keep these contracts stable.

## Architecture

- Target: **i686 (32-bit x86)**, no FPU/SSE assumptions in the ABI.
- Executables: **ELF32**, `ET_EXEC`, `EM_386`, statically linked, no PIE.
- Endianness: little-endian.

## Address space layout (per process)

| Range                     | Use                                    |
|---------------------------|----------------------------------------|
| `0x00000000 – 0x00FFFFFF` | kernel identity map (low 16 MiB), supervisor-only |
| `0x40000000`              | user program load base (ELF segments)  |
| `0x50000000 – ...`        | user heap (`sbrk`/`malloc`), grows up   |
| `... – 0xC0000000`        | user stack (top at `0xC0000000`), grows down |
| `0xC0000000 – 0xFFFFFFFF` | kernel space (heap, page tables, shared across all address spaces) |

Each process has its own page directory. Kernel mappings (low identity map and
everything ≥ `0xC0000000`) are shared by reference across all address spaces.

## System call convention

Syscalls are made with `int $0x80`:

| Register | Meaning              |
|----------|----------------------|
| `eax`    | syscall number       |
| `ebx`    | arg1                 |
| `ecx`    | arg2                 |
| `edx`    | arg3                 |
| `eax`    | return value         |

- Return values are signed 32-bit. Errors are negative (typically `-1`).
- Pointers passed to syscalls are user virtual addresses in the caller's
  address space; the kernel accesses them directly (no separate copy ABI yet).
- Numbers are defined once in `include/syscall_abi.h`, shared by kernel and
  userspace. **Do not renumber existing calls; only append.**

## Program startup

The kernel builds the initial user stack as:

```
[esp]      argc
[esp+4]    argv[0]
...
[esp+4*argc]   NULL          (argv terminator)
<argument strings>
```

`crt0.S` (`user/crt0.S`) reads this, calls `int main(int argc, char **argv)`,
and on return performs `exit(main_ret)`.

## C runtime

Programs link against the mini libc (`user/libc/`, header `user/libc.h`):
syscall wrappers, `printf`/`fprintf`, `malloc`/`free` (over `sbrk`), and basic
string/memory functions.

See also: [SYSCALLS.md](SYSCALLS.md), [PROCESS_MODEL.md](PROCESS_MODEL.md),
[VFS.md](VFS.md), [IPC.md](IPC.md).
