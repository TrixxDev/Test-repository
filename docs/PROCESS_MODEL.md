# AuroraOS Process Model

## Definitions

- **Process** (`process_t`, `kernel/process.h`) = address space (page
  directory) + file descriptor table + IPC mailbox + lifecycle state + a thread.
- **Thread** (`struct thread`, `kernel/scheduler.c`) = a schedulable execution
  context: saved kernel stack pointer, the page directory to load, a kernel
  stack, and a run state.

Currently one thread per process; the structures allow more later.

## Process control block

```
process_t {
    pid, ppid
    uid                // owner: 0 = root, else a user
    pd_phys            // address space (CR3 value)
    state              // RUNNING / ZOMBIE / UNUSED
    exit_code
    fds[MAX_FDS]       // file descriptor table (FD_NORMAL/PIPE/SOCKET)
    user_brk           // top of the user heap (sbrk)
    thread             // the process's thread
    parent
    saved_regs         // fork: frame the child resumes from
    mbox_*             // IPC message queue
}
```

`pid 0` is the kernel itself (the boot thread). `pid 1` is `init`.

## uid (security foundation)

Each process has a `uid`, inherited across `fork`/`exec`/spawn. The kernel and
its services (init, logger, netd) run as **root (uid 0)**; `init` starts the
shell with `setuid(1000)`, so the shell and everything it launches run as an
unprivileged **user (uid 1000)** — `id` in the shell shows it. `setuid` only
drops privilege (root may set any uid; a non-root process may not lower its uid
number), and the privileged `sock_link` syscall is rejected for non-root. This
is the groundwork for rwx permissions on VFS nodes (see
[../NEXT_STEPS.md](../NEXT_STEPS.md)); those are not enforced yet.

## Lifecycle

```
        spawn / fork
             |
             v
        +----------+    exit()    +---------+   wait() by parent   +--------+
        | RUNNING  | -----------> | ZOMBIE  | -------------------> | UNUSED |
        +----------+              +---------+                      +--------+
             ^  |
       block |  | wake (IRQ / IPC / child exit)
             |  v
        (BLOCKED thread state)
```

- **exit**: closes fds, frees the user address space
  (`vmm_destroy_address_space`), drops IPC state, marks the process `ZOMBIE`,
  wakes a waiting parent, then switches away forever.
- **wait**: finds a `ZOMBIE` child, reads its exit code, frees the child's
  kernel stack + thread + PCB. Blocks if children exist but none have exited.
- Cleanup is explicit: kernel stack, page tables, user frames, and PCB are all
  reclaimed.

## fork / exec

- **fork** (`do_fork`): creates a new address space, copies every present user
  page (no COW yet), inherits the fd table (shared open files, refcounted),
  copies the syscall frame with `eax = 0` for the child, and creates a thread
  that returns to ring 3 via `return_to_user`.
- **exec** (`do_exec`): loads a new ELF into a fresh address space, builds
  `argc`/`argv` on the new stack, frees the old address space, and jumps to the
  new entry point. The pid and fds are preserved.

## Scheduling

- Preemptive round-robin over a circular list of threads, driven by the PIT
  (100 Hz) via a tick hook.
- Run states: `READY`, `BLOCKED`, `ZOMBIE`. `schedule()` picks the next
  `READY` thread.
- Context switch (`switch.S`) saves/restores callee-saved registers; the
  scheduler also reloads `CR3` (address space) and `TSS.esp0` (ring-0 stack).
- An **idle thread** is always `READY` so the CPU can `hlt` with interrupts on
  when every other thread is blocked, allowing IRQs to wake them.

## Reparenting and reaping

- When a process exits, its still-living children are **reparented to init**
  (`reparent_to_init`); init's `wait()` loop then reaps them. This prevents
  leaked zombies as the number of services grows.
- `wait(status, WNOHANG)` is non-blocking; the shell calls it each prompt to
  **auto-reap finished background jobs** (`cmd &`).
- `kill(pid)` forcibly terminates another process: it frees the target's
  address space, fds, mailbox and thread, marks it a zombie, and reparents its
  children. Used as the force-kill fallback during shutdown.

## Supervision and shutdown

`init` (pid 1) starts services and `wait()`s in a loop, restarting daemons that
die and reaping adopted orphans. **Graceful shutdown** (when the shell exits):
init sends a `"shutdown"` message to each service, waits for it to stop, and
falls back to `kill()` if it does not exit in time. Then init exits and the
kernel reaps it.
