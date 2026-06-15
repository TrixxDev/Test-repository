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
| 7  | `open`   | `open(const char *path, int flags) -> fd` | Open a VFS path. |
| 8  | `read`   | `read(int fd, void *buf, uint len) -> n` | Read; `0` = EOF. May block (console/pipe). |
| 9  | `write`  | `write(int fd, const void *buf, uint len) -> n` | Write. |
| 10 | `close`  | `close(int fd)` | Close a descriptor. |
| 11 | `getpid` | `getpid() -> pid` | Current process id. |
| 12 | `pipe`   | `pipe(int fd[2]) -> 0/-1` | Create a pipe (`fd[0]` read, `fd[1]` write). |
| 13 | `dup2`   | `dup2(int oldfd, int newfd) -> newfd` | Duplicate a descriptor onto `newfd`. |
| 14 | `sbrk`   | `sbrk(int incr) -> old_brk` | Grow the user heap; returns the previous break. |
| 15 | `msgsend`| `msgsend(int pid, const void *buf, int len) -> 0/-1` | Send an IPC message to a process. |
| 16 | `msgrecv`| `msgrecv(void *buf, int len, int *from) -> n` | Block until a message arrives; returns length, sets sender pid. |
| 17 | `register` | `register(const char *name) -> 0/-1` | Register the current pid under a service name. |
| 18 | `lookup` | `lookup(const char *name) -> pid/-1` | Resolve a service name to a pid. |
| 19 | `kill`   | `kill(int pid) -> 0/-1` | Forcibly terminate another process (force-kill fallback for shutdown). |
| 20 | `socket` | `socket(int domain, int type) -> fd/-1` | Create an unconnected socket endpoint (AF_LOOPBACK / SOCK_STREAM). Backed by an fd, so `read`=recv, `write`=send, `close` tear it down. |
| 21 | `sock_link` | `sock_link(int handle_a, int handle_b) -> 0/-1` | Join two unconnected endpoints into a connected pair. Each handle is `SOCK_HANDLE(pid, fd)`. **Root only** — the `netd` broker uses it; ordinary processes get `-1`. |
| 22 | `poll`   | `poll(struct pollfd *fds, int nfds, int timeout) -> nready/-1` | Wait for descriptors to become ready (`POLLIN`/`POLLOUT`, or `POLLERR`). `timeout==0` polls once; otherwise blocks until a socket peer makes progress. |
| 23 | `getuid` | `getuid() -> uid` | Owner uid of the calling process. |
| 24 | `setuid` | `setuid(int uid) -> 0/-1` | Drop privilege: root may set any uid; a non-root process may not lower its uid number. |

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
