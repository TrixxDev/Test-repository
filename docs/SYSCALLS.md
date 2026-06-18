# AuroraOS System Calls

Invoked via `int $0x80` (`eax` = number, `ebx`/`ecx`/`edx` = args, `eax` =
return). Numbers are defined in `include/syscall_abi.h` and dispatched in
`kernel/syscall.c`. The libc wrappers live in `user/libc.h`.

| # | Name | Signature | Description |
|---|------|-----------|-------------|
| 1  | `putc`   | `putc(char c)` | Write one char to the console. |
| 2  | `yield`  | `yield()` | Voluntarily reschedule. |
| 3  | `exit`   | `exit(int code)` | Terminate the calling process. No return. |
| 4  | `fork`   | `fork() -> pid` | Duplicate the process. Returns child pid to the parent, `0` to the child. |
| 5  | `exec`   | `exec(const char *path, char **argv)` | Replace the process image. No return on success. |
| 6  | `wait`   | `wait(int *status, int flags) -> pid` | Reap an exited child. Blocks unless `flags & WNOHANG` (then `0` if none ready). `-1` if no children. |
| 7  | `open`   | `open(const char *path, int flags) -> fd` | Open a VFS path. `flags` is the access mode (`O_RDONLY`/`O_WRONLY`/`O_RDWR`); the open is permission-checked (`VFS_R`/`VFS_W`). |
| 8  | `read`   | `read(int fd, void *buf, uint len) -> n` | Read; `0` = EOF. May block (console/pipe). |
| 9  | `write`  | `write(int fd, const void *buf, uint len) -> n` | Write. |
| 10 | `close`  | `close(int fd)` | Close a descriptor. |
| 11 | `getpid` | `getpid() -> pid` | Current process id. |
| 12 | `pipe`   | `pipe(int fd[2]) -> 0/-1` | Create a pipe (`fd[0]` read, `fd[1]` write). |
| 13 | `dup2`   | `dup2(int oldfd, int newfd) -> newfd` | Duplicate a descriptor onto `newfd`. |
| 14 | `sbrk`   | `sbrk(int incr) -> old_brk` | Grow the user heap; returns the previous break. |
| 15 | `msgsend`| `msgsend(int pid, const void *buf, int len) -> 0/-1` | Send an IPC message to a process. |
| 16 | `msgrecv`| `msgrecv(void *buf, int len, int *from) -> n` | Block until a message arrives; returns length, sets sender pid. OR `MSG_NOWAIT` into `len` (libc `msgrecv_nb`) to return `-1` immediately when the mailbox is empty instead of blocking — lets a single-mailbox event loop drain a burst. |
| 17 | `register` | `register(const char *name, uint mode) -> 0/-1` | Register the current pid under a service name with a permission `mode` (libc `svc_register` defaults to `0644`). Re-registering a name is allowed only for its owner or root. |
| 18 | `lookup` | `lookup(const char *name) -> pid/-1` | Resolve a service name to a pid. Requires "read" permission on the service (`-1` if denied or absent). |
| 19 | `kill`   | `kill(int pid) -> 0/-1` | Forcibly terminate another process (force-kill fallback for shutdown). |
| 20 | `socket` | `socket(int domain, int type) -> fd/-1` | Create an unconnected socket endpoint (AF_LOOPBACK / SOCK_STREAM). Backed by an fd, so `read`=recv, `write`=send, `close` tear it down. |
| 21 | `sock_link` | `sock_link(int handle_a, int handle_b) -> 0/-1` | Join two unconnected endpoints into a connected pair. Each handle is `SOCK_HANDLE(pid, fd)`. **Root only** — the `netd` broker uses it; ordinary processes get `-1`. |
| 22 | `poll`   | `poll(struct pollfd *fds, int nfds, int timeout) -> nready/-1` | Wait for descriptors to become ready (`POLLIN`/`POLLOUT`, or `POLLERR`). `timeout==0` polls once; otherwise blocks until a socket peer makes progress. |
| 23 | `getuid` | `getuid() -> uid` | Owner uid of the calling process. |
| 24 | `setuid` | `setuid(int uid) -> 0/-1` | Drop privilege: root may set any uid; a non-root process may not lower its uid number. |
| 25 | `uid_of` | `uid_of(int pid) -> uid/-1` | Owner uid of another process (e.g. so `netd` can enforce privileged ports without trusting the request). |
| 26 | `fb_map` | `fb_map(uint info[3]) -> vaddr/0` | Map the active framebuffer into the caller and fill `info` = {width, height, pitch}; `0` if no framebuffer. Used by the `windowserver`. |
| 27 | `fb_active` | `fb_active() -> 1/0` | Whether a graphics framebuffer is up; lets `init` choose the GUI vs the text session. |
| 28 | `mouse` | `mouse_read(int out[3]) -> 0` | Block for one PS/2 pointer event; fills `out` = {dx, dy, buttons} (dy>0 = down; buttons bit0/1/2 = L/R/M). Used by the `windowserver` mouse helper. |
| 29 | `readdir` | `readdir(const char *path, int index, struct dirent *out) -> 1/0/-1` | Enumerate directory `path`: fills `out` = {name, type (`DT_FILE`/`DT_DIR`), size} for entry `index`. `1` = filled, `0` = past the last entry, `-1` = error (not a directory / no read permission). Permission-checked (`VFS_R`) like `open`. Used by the Finder (`Aurora Files`). |
| 30 | `halt` | `halt() -> -1 on error, else no return` | Power off the machine (root only): tries the QEMU/Bochs ACPI poweroff ports, then halts the CPU. Used by the Aurora menu's **Shut Down**. |
| 31 | `sysinfo` | `sysinfo(struct sysinfo *out) -> 0/-1` | Fill `out` = {ram_kb, ram_used_kb, free_frames, procs, uptime_ms}. Used by the Settings **System** pane. |
| 32 | `sleep` | `msleep(int ms) -> 0` | Block the calling thread for ~`ms` milliseconds (10 ms granularity; PIT is 100 Hz). Backed by a PIT-driven sleeper queue in the scheduler (no busy-wait). Used by the window server's fixed-cadence render ticker. |
| 33 | `uiscale` | `ui_scale() -> pct`, `ui_scale_set(pct)` | Read or publish the UI scale (percent, 100..200). `set` >= 100 from **root** updates the kernel's canonical value (the window server publishes the user's Settings → Display choice); any other call just reads it. GUI apps query it (`ui_scale()`) to lay out their content to match the scaled chrome. |
| 34 | `fbmode` | `fb_set_mode(w, h) -> 1/0` | Change the display resolution at runtime (**root only**; Bochs-VBE path). Re-runs the VBE mode-set and re-maps the (same physical) framebuffer at the new geometry; the window server then re-maps it (`fb_map`), resizes its buffers and repaints. Returns 0 if unsupported (e.g. a fixed GRUB framebuffer). |
| 35 | `shmget` | `shm_create(size, flags) -> id/-1` | Allocate a shared-memory object of `size` bytes (whole frames). `flags` may be `SHM_PUBLIC` (any process may map it, e.g. the clipboard). The creator owns its lifetime; used by the window server for zero-copy window surfaces. |
| 36 | `shmmap` | `shm_map(id) -> vaddr/0` | Map shared object `id` into the caller at its fixed slot address (same address in every mapper). **Access-controlled**: succeeds only for the creator, the client the creator granted (`shmgrant`), or a public object. Each mapping holds a reference; idempotent per process. |
| 37 | `shmdel` | `shm_destroy(id) -> 0/-1` | **Creator only.** Unmap object `id` from the caller, mark it destroyed, and free its frames once no address space still maps it (deferred free). A creator's exit destroys its objects the same way. |
| 38 | `shmunmap` | `shm_unmap(id) -> 0/-1` | Drop the caller's mapping of object `id` (decrements the reference count; frees the frames if this was the last mapper of a destroyed object). A process's exit/exec releases all its mappings automatically. |
| 39 | `shmgrant` | `shm_grant(id, pid) -> 0/-1` | **Creator only.** Authorize process `pid` to `shm_map` object `id`. The window server grants each window's surface to its owning app; the clipboard uses `SHM_PUBLIC` instead. |

## Notes

- `fd` 0/1/2 are stdin/stdout/stderr, wired to the console device, inherited
  across `fork` and preserved across `exec`.
- `read`/`msgrecv`/`wait` block the calling thread; an always-runnable idle
  thread lets device IRQs wake blocked processes.
- `exec` always passes at least `argv[0]` (the path) if the caller passes no
  argv.
- Sockets reuse the fd machinery: there is no separate `send`/`recv`/`bind`/
  `connect`/`accept` syscall. `send`/`recv` are `write`/`read`; `bind`/`connect`/
  `accept` are libc RPCs to `netd` (see [NETWORKING.md](NETWORKING.md)). The only
  socket syscalls are `socket`, `sock_link` and `poll`.

Adding a syscall: append a number in `syscall_abi.h`, implement the backend
(usually in `kernel/process.c`), add a `case` in `kernel/syscall.c`, and a
wrapper in `user/libc.h`. Update this file.
