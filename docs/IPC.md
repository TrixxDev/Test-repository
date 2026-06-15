# AuroraOS IPC

AuroraOS has two complementary inter-process mechanisms: **pipes** (byte
streams, ideal for the shell) and **message passing** with a **named service
registry** (datagrams, ideal for services/daemons).

## Pipes

Anonymous byte-stream channels (`kernel/pipe.c`).

- `pipe(int fd[2])` creates a pipe: `fd[0]` is the read end, `fd[1]` the write
  end. Each end is a VFS node over a shared ring buffer.
- Backed by a blocking ring buffer:
  - read blocks while empty and there are writers; returns `0` (EOF) once all
    write ends are closed;
  - write blocks while full and there are readers; returns `-1` (broken pipe)
    once all read ends are closed.
- Read/write ends are reference counted. `fork` and `dup2` share file objects
  (refcounted); an end is only torn down when its last descriptor closes.
- `dup2(oldfd, newfd)` redirects a descriptor — the basis for connecting a
  pipe to stdin/stdout.

### Shell pipelines

For `a args | b args`, the shell:

```
pipe(p);
fork(); // child A: dup2(p[1],1); close(p[0]); close(p[1]); exec(a)
fork(); // child B: dup2(p[0],0); close(p[0]); close(p[1]); exec(b)
close(p[0]); close(p[1]);
wait(); wait();
```

Verified: `cat /disk/poem.txt | grep aurora`.

## Message passing

Datagram mailboxes attached to processes (`kernel/process.c`).

- `msgsend(int pid, const void *buf, int len)` — copies up to `MSG_MAX` (256)
  bytes into the target's mailbox and wakes it. Non-blocking; fails if the
  target is gone or its mailbox is full.
- `msgrecv(void *buf, int len, int *from)` — blocks until a message is queued,
  then returns its length and the sender pid.
- Each message records the sender's pid; mailboxes are bounded (back-pressure
  via `-1` on overflow). Pending messages are freed when a process exits.

## Named service registry

So clients can find services without hardcoding pids:

- `register(const char *name, mode)` — bind the current pid to a name with a
  permission `mode` (libc `svc_register` defaults to `0644`; `svc_register_mode`
  sets it explicitly). Re-registering an existing name is allowed only for its
  owner or root, so an unprivileged process cannot **hijack** a service name.
- `lookup(const char *name) -> pid` — resolve a name to a pid (`-1` if absent
  **or not permitted**).
- Entries are removed when the owning process exits.

### Service permissions (Phase 8A.5)

Each service has an `owner_uid` and a `mode`; the "read" bit gates **lookup**
(discovery). `0644` is a public service (anyone may look it up — `log` and `net`
are public, since the unprivileged shell uses them); `0600` is private (only the
owner/root may resolve it), which is how a future admin daemon (e.g. `aurorad`)
would be locked down. `msgsend` itself is not uid-gated — knowing a pid is the
capability, and the lookup gate controls who can obtain it.

### Service model

```
kernel
  └─ init (pid 1, root)
       ├─ logger   (root; registers "log"; msgrecv loop -> console)
       ├─ netd     (root; registers "net"; brokers loopback sockets)
       └─ shell    (uid 1000; lookup "log"/"net"; msgsend requests)
```

Verified: the shell's `log <text>` builtin resolves `"log"` and sends a
message; the logger daemon prints `[log] (pid N) <text>`.

The same registry + message passing underpins **sockets**: `bind`/`connect`/
`accept` are RPCs to `netd` (registered as `"net"`), which then joins the two
kernel socket endpoints. See [NETWORKING.md](NETWORKING.md).

## Design notes

- Pipes are for streaming and composition; messages are for request/response
  and service communication.
- Future services (network daemon, window server, etc.) are expected to be
  ordinary userspace processes reachable via the registry + message passing —
  not kernel code.
