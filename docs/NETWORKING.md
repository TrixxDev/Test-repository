# AuroraOS Networking — Phase 8A (loopback)

Networking is built the same way as the rest of the system: the **stack lives in
userspace**, the kernel provides only mechanism. Phase 8A implements
`AF_LOOPBACK` (in-machine) stream sockets, with no NIC and no driver, so the
socket API and the daemon boundary can be exercised deterministically before any
hardware exists. Phase 8B will add a real Ethernet/IP stack behind the same
boundary.

## Division of labour

```
                         ring 3 (userland)
   echocli ── echosrv          netd  (the "stack": ports + rendezvous)
      │  socket/poll  │          │
      │  bind/connect/accept (msg IPC RPC)
      └──────── int 0x80 ───────┴──────────────┐
================ ring 0 (kernel) ===============│=========
   socket syscalls (mechanism only):           ▼
     socket()      create an endpoint (fd)
     sock_link()   join two endpoints (root only — netd)
     poll()        readiness wait
     read/write    recv/send over a connected endpoint
```

- **Kernel (`kernel/socket.c`)** — pure mechanism. A `struct socket` is a
  connectable, bidirectional byte-stream **endpoint** backed by a VFS node, so it
  lives in the fd table and works with `read`/`write`/`close`/`poll` like any
  other descriptor. The kernel knows nothing about ports, addresses or protocols.
  A connected pair shares one `sock_conn` holding two ring buffers (one per
  direction), mirroring the blocking/wake discipline of `kernel/pipe.c`; the
  shared object is freed only once both ends close, so there is never a dangling
  peer pointer.
- **netd (`user/netd.c`)** — the stack/policy. It owns the `AF_LOOPBACK` port
  namespace and the bind/connect/accept rendezvous. It is the control plane: it
  brokers a connection, then joins the two endpoints with the privileged
  `sock_link()` syscall, after which data flows endpoint-to-endpoint **without
  passing back through netd**. netd never blocks on the kernel — it only replies
  once a rendezvous completes, so it stays a responsive single-threaded broker.

This keeps the part that becomes real in 8B (ports, handshake, routing) in netd,
while the kernel only moves bytes between two connected endpoints — which is not
a "stack", it is what pipes already do.

## The socket API (libc)

```c
int s = socket(AF_LOOPBACK, SOCK_STREAM);   /* syscall: create endpoint   */
bind(s, PORT_ECHO);                          /* RPC -> netd: claim a port  */
listen(s);                                   /* no-op for loopback         */
int c = accept(PORT_ECHO);                   /* RPC -> netd: get a client  */
recv(c, buf, n);  send(c, buf, n);           /* = read()/write() on the fd */
close(c);
```

`socket`/`poll`/`close`/`send`/`recv` are thin syscalls. `bind`/`listen`/
`connect`/`accept` (in `user/libc/net.c`) are message-passing RPCs to netd,
found in the service registry under `"net"`. The wire contract is
`include/net.h` (`net_req_t` / `net_rep_t`).

## Connection handshake

A kernel socket is named across processes by a packed `SOCK_HANDLE(pid, fd)` so
netd can refer to either side. The listening socket is just a marker; each
`accept` creates a *fresh* endpoint to be connected.

```
server                          netd                         client
------                          ----                         ------
socket(); bind(p) ───BIND p───►  record port p
accept(p):
  c=socket()    ───ACCEPT p,c─►  queue (srv, c)        socket()
                                                       connect(c2,p):
                                 ◄──CONNECT p,c2─────── (blocks)
                                 match: sock_link(c2, c)
                  ◄──OK (accept)─ reply both ──OK (connect)►
recv/send on c  ◄═══ data flows endpoint↔endpoint ═══►  recv/send on c2
```

Either side may arrive first; netd keeps a small queue of pending accepts and
pending connects per port and matches them. A `connect` to an unbound port fails
immediately; `connect` to a bound-but-not-yet-accepting port blocks until the
server accepts.

## poll()

`poll(struct pollfd *fds, int nfds, int timeout)` reports `POLLIN` (readable, or
EOF), `POLLOUT` (writable) and `POLLERR` (peer gone). `timeout == 0` polls once;
otherwise it blocks until a socket peer makes progress, by registering the caller
as a poll-waiter on each socket and being woken by the peer's send/recv/close.
The echo server uses it to wait for client data. Limitations (first cut):
non-socket fds are reported as always-ready (pipes/console don't have poll ops
yet), and `timeout` is treated as "block until ready" rather than a real
deadline — a tick-driven timeout is future work.

## Security note

`sock_link` is a privileged broker primitive: the kernel rejects it unless the
caller's uid is 0. netd runs as root; the shell and the echo programs run as
uid 1000 and reach netd only through the message RPCs. This is the first use of
the new uid foundation (see [PROCESS_MODEL.md](PROCESS_MODEL.md)).

## Demo

```
aurora> echosrv &                 # binds loopback port 7 via netd
aurora> echocli hello-loopback    # client -> netd -> server -> echo back
[echocli] sent: hello-loopback
[echocli] echo: hello-loopback
```

## Explicitly out of scope for Phase 8

TLS, HTTPS, IPv6, DHCP, Wi-Fi. Phase 8B is the first real wire: a NIC driver
(virtio-net / rtl8139) and ARP → IPv4 → UDP → TCP → DNS, behind the same netd
boundary.
