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

- `sock_link` is a privileged broker primitive: the kernel rejects it unless the
  caller's uid is 0. netd runs as root; the shell and the echo programs run as
  uid 1000 and reach netd only through the message RPCs.
- **Privileged ports:** binding a port below `PORT_PRIVILEGED` (1024) requires
  root. netd enforces this by asking the kernel for the requester's uid
  (`uid_of(from)`) rather than trusting the request, so it cannot be forged. The
  echo demo therefore uses port **7000** (unprivileged), which the uid-1000
  server may bind; an attempt to bind, say, port 80 as a user is rejected.

These build on the uid foundation (see [PROCESS_MODEL.md](PROCESS_MODEL.md)) and
the service-permission model (see [IPC.md](IPC.md)).

## Demo

```
aurora> echosrv &                 # binds loopback port 7000 via netd
aurora> echocli hello-loopback    # client -> netd -> server -> echo back
[echocli] sent: hello-loopback
[echocli] echo: hello-loopback
```

## Explicitly out of scope for Phase 8A

TLS, HTTPS, IPv6, DHCP, Wi-Fi. Phase 8B is the first real wire: a NIC driver
(virtio-net / rtl8139) and ARP → IPv4 → UDP → TCP → DNS, behind the same netd
boundary.

---

# AuroraOS Networking — Phase 8B (the first real wire)

Phase 8B brings up a **hardware NIC** and a raw Ethernet transport beneath the
loopback layer above. The transport (`drivers/virtio_net.c`) is deliberately the
*only* piece that touches the device; every protocol layer to come (Ethernet
dispatch, ARP, IPv4, UDP, TCP) is plain logic built on its two primitives.

```
   ARP / IPv4 / UDP / TCP   (logic — built next, no DMA)
        net_send_frame() ▲ ▼ net_recv_frame()
   ┌──────────────────────────────────────────┐
   │  virtio_net.c  — transport (the only      │
   │  code that talks to the device + DMA)     │
   └──────────────────────────────────────────┘
        virtqueues (RX=0, TX=1) in DMA memory
   ┌──────────────────────────────────────────┐
   │  pci.c — config space, BAR0, bus-master   │
   └──────────────────────────────────────────┘
```

## The transport (`drivers/virtio_net.c`)

Legacy/transitional **virtio-net** (PCI vendor `0x1AF4`, device `0x1000`). The
legacy virtio-pci interface is a small block of I/O registers behind BAR0; bring-
up is the standard handshake: reset → `ACK` → `DRIVER` → negotiate features
(we offer **none** — guest features = 0, so the device uses the 10-byte legacy
`virtio_net_hdr` and never merges RX buffers) → read the MAC → set up the
queues → `DRIVER_OK`.

A **virtqueue** is a descriptor table + an *available* ring (driver→device) + a
*used* ring (device→driver), one contiguous page-aligned region whose page number
is handed to the device via `QUEUE_PFN`. virtio-net uses queue 0 for RX and queue
1 for TX. `vq_setup()` carves one out of a static buffer and registers it.

### DMA without a DMA allocator

This kernel identity-maps low physical memory (phys == virt), so a page-aligned
**static BSS buffer's address is also its physical address**. The rings and packet
buffers therefore live in `__attribute__((aligned(4096))) static uint8_t[...]`
arrays and are handed to the device directly — no DMA allocator is needed yet.
This is the single most load-bearing assumption in the driver; if the kernel ever
moves to a higher-half / non-identity layout, the transport needs a real
phys↔virt translation here and **nowhere else**.

### The two primitives

```c
int net_send_frame(const void *data, unsigned len);   /* TX one Ethernet frame */
int net_recv_frame(void *buf, unsigned cap);          /* RX one, or 0 if none  */
```

- **TX** stages `[10-byte zero hdr][frame]` in a static buffer, posts one
  descriptor, publishes it on the available ring, notifies the device, then
  bounded-polls the used ring for completion.
- **RX** pre-posts 16 device-writable buffers (`rx_fill()`). `net_recv_frame()`
  drains the used ring, strips the virtio header, copies out one frame, and
  recycles the descriptor back to the device.
- The **IRQ** handler (IRQ11 → vector 43) only reads the ISR to ack the device
  and bumps a counter; RX is polled. This is intentional (see *IRQ storm* below).

## Architecture review — what was hardened before going up the stack

Phase 8B is the first code that ingests data from **outside the machine**, so —
mirroring the SHM and graphics reviews — the transport was audited and hardened
before any protocol logic was layered on top.

### 1. Inbound bounds checking

Everything the **device** reports about a received buffer is treated as
untrusted. `net_recv_frame()` validates each used-ring entry before copying:

| Field | Check | On failure |
|-------|-------|-----------|
| descriptor `id` | `id < RX_BUFS` | drop (`rx_dropped++`), cannot recycle |
| length | `>= NET_HDR_LEN + ETH_MIN` (14) | drop runt (`rx_errors++`), recycle |
| length | `<= RX_BUF_SZ` and payload `<= ETH_MAX` (1514) | drop oversize (`rx_errors++`), recycle |
| copy size | `min(payload, caller cap)` | clamp — never overruns either buffer |

TX is symmetric: `net_send_frame()` rejects `len < 14` or `len > 1514` before it
ever touches a descriptor (`tx_dropped++`).

### 2. RX-ring exhaustion

The earlier draft returned **after a single used entry** and returned `0` for
both "queue empty" *and* "frame dropped" — so one runt could mask the real frame
behind it, and a burst could appear to stall the ring. The hardened version
**drains in a loop**: it pulls and recycles every used entry until it finds one
plausible frame to return (or the ring is genuinely empty), so a flood of
runts/garbage can neither wedge the ring nor hide a good frame. Buffers are
recycled the instant they are consumed, so the 16-deep ring keeps cycling as long
as anything polls it. (If inbound out-runs the poller, the *device* drops the
excess — backpressure lives on the device side, never as a guest-side leak.)

### 3. IRQ-storm resistance

A classic first-stack failure is doing real work in the IRQ: a packet flood then
becomes an interrupt flood that starves the compositor. AuroraOS sidesteps this
by design — **the ISR does no work**: it acks the device and increments a counter,
nothing more. All RX processing happens in polled context at the upper layers'
pace, so inbound load can never preempt the GUI render loop.

### 4. Per-interface statistics

The transport keeps counters (`struct net_stats`): `rx/tx_packets`,
`rx/tx_bytes`, `rx/tx_dropped`, `rx/tx_errors`, `rx_irqs`. They are exposed via
`SYS_NETSTAT` (libc `netstat()`) and surfaced in **Settings → System** (NIC up,
MAC, RX/TX packets, dropped). This pays for itself immediately when debugging
IPv4 — a malformed packet shows up as a `dropped`/`error` tick instead of a
silent black hole.

## Verification

```
qemu-system-i386 -kernel aurora.elf -m 64M -drive file=disk.img,format=raw,if=ide \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -object filter-dump,id=d0,netdev=n0,file=/tmp/net.pcap -serial file:/tmp/log
```

At boot the driver sends an ARP "who-has 10.0.2.2" and waits for the reply. A
healthy run shows both frames in the pcap and matching counters on the serial:

```
[net] virtio-net up: io=0xc000 irq=11 mac=52:54:00:12:34:56 feat=0x79bf8064
[net] rx 64 bytes src=52:55:0a:00:02:02 type=0x0806      # SLIRP's ARP reply
[net] stats rx=1/64 tx=1/42 drop=0/0 err=0/0 irq=1
```

```
frame 1: 42 bytes ethertype=0x0806 src=52:54:00:12:34:56  # our request
frame 2: 64 bytes ethertype=0x0806 src=52:55:0a:00:02:02  # gateway reply
```

## Roadmap (logic on top of the proven transport)

The transport is done and audited; everything below is protocol logic over
`net_send_frame`/`net_recv_frame`, with no further DMA risk.

| Phase | Layer | Done = | Status |
|-------|-------|--------|--------|
| 4 | **Ethernet** dispatch (`net/eth.c`) — split frames by EtherType → ARP / IPv4 | frames routed by type | ✅ |
| 5 | **ARP** cache (`net/arp.c`, EMPTY/PENDING/RESOLVED, 60 s TTL) + reply to requests | host can `arp` us; we resolve the gateway | ✅ |
| 6 | **IPv4** (`net/ipv4.c`) RX/TX + header checksum, **fragments dropped**; **ICMP** echo (`net/icmp.c`) | **`ping 10.0.2.2` — 4/4 replies** | ✅ |
| 7 | **UDP** (`net/udp.c`) — `udp_send` / `udp_bind`, no sockets | **`nc -u` round-trip Aurora ↔ host** | ✅ |
| 7.5 | **DNS** over UDP (`net/dns.c`) — typed `dns_query(name, type)` | **`example.com` → real A record** | ✅ |
| 8.1 | **TCP** connect (`net/tcp.c`) — handshake only, full TCB + state enum | **`connect 10.0.2.2:80` → ESTABLISHED** | ✅ |
| 8.2 | TCP `send`/`recv` (data, no close) | `GET / HTTP/1.0` returns bytes | next |
| 8.3 | TCP teardown (FIN / TIME_WAIT) | clean close | later |

## Phase 8.1 — TCP handshake (client connect only)

TCP is scoped hard for the first cut: **client `connect()` only**, no listen/
accept, no data transfer, no retransmission / congestion control / SACK / window
scaling / keepalive. But the **TCB** (`struct tcp_tcb`) and the **state enum**
are the full RFC 793 shape from day one, so later phases never renumber or
rewrite — only `CLOSED → SYN_SENT → ESTABLISHED` are reached now.

`tcp_connect(dst, port)` picks an ephemeral port + ISS, sends a SYN, and enters
`SYN_SENT`. `tcp_input` (dispatched from `ipv4_input` for `IPPROTO_TCP`) verifies
the mandatory TCP checksum (pseudo-header + segment), matches the 4-tuple, and on
a `SYN+ACK` acking our SYN records the peer's ISN, sends the final `ACK`, and
moves to `ESTABLISHED`. An `RST` drops the connection to `CLOSED`.

Verified through SLIRP (`tools/tcptest.py`, a host listener on :80):

```
[tcp] connect 10.0.2.2:80
[tcp] state=ESTABLISHED -- HANDSHAKE OK
```

pcap: `SYN` → `SYN|ACK` → `ACK`. Because this isolated TCP sits on a proven
L2–L3 base, a handshake failure can only be a TCP bug — not DMA, the driver, ARP
or IPv4.

## Phase 7.5 — DNS (resolve a real name)

`dns_query(name, type, &ip)` sends a recursion-desired query to the SLIRP DNS
server (10.0.2.3:53), which forwards to the host's resolver, and parses the
answer (skipping the echoed question and any CNAME records, handling name
compression). The API takes a record **type** (`DNS_A`/`DNS_AAAA`/`DNS_CNAME`)
from day one so adding AAAA later won't change callers — only A is parsed today.

```
[dns] example.com -> 104.20.23.154        # real A record from the internet
[ping] example.com
[icmp] PING 104.20.23.154 : 2 packets ...
```

This is the first user-visible leap: the OS resolves a real name on its own.
Pinging the resolved address additionally needs **outbound ICMP to the
internet**, which depends on the environment's network policy (the on-link
gateway ping proves the ICMP path regardless).

> Note: the net stack currently lives in the kernel for bring-up. As TCP and
> user-facing networking arrive, resolution/transport move behind the existing
> `netd` boundary (see Phase 8A) so TCP is not hard-wired into the kernel.

## Phase 7 — UDP (datagrams, no sockets yet)

Two calls, exactly the minimal surface: `udp_send(dst, src_port, dst_port,
payload, len)` fires a datagram (next hop via `ipv4_send` → `arp_resolve`), and
`udp_bind(port, handler)` registers a callback for an inbound port. `udp_input`
demuxes by destination port to the bound handler. UDP checksums are optional over
IPv4 (RFC 768), so TX sends 0 ("not computed") and RX skips verification — the
substrate DNS/NTP/syslog will sit on. User-visible sockets come later.

Verified through SLIRP's NAT with `tools/udptest.py` (a host listener on 9999 —
equivalent to `nc -u -l 9999`):

```
[host] <- guest: b'hello from aurora\n'
[host] -> guest: reply from host
[udp] rx 16 bytes from 10.0.2.2:9999: "reply from host"
[udp] 1 datagram(s) received -- UDP RX OK
```

pcap shows UDP 9999→9999 out (TX), in (RX), and the guest's echo — both
directions over a single NAT mapping, no `hostfwd` needed.

## Phase 6 — IPv4 + ICMP (the ping milestone)

IPv4 is deliberately minimal. **RX** (`ipv4_input`) accepts a packet only if it
is version 4, IHL ≥ 5, **not a fragment** (`frag_off & 0x3FFF == 0`, DF ignored),
its header checksum verifies, and its destination is our IP — anything else is
counted and dropped. **TX** (`ipv4_send`) builds just a 20-byte header + payload
+ checksum: no options, no fragmentation, no broadcast/multicast. The next hop is
resolved through `arp_resolve()` (on-link direct, off-link via the gateway), so
the IP layer never touches the ARP cache directly and returns *pending* if the
MAC isn't known yet — the caller simply retries.

**ICMP** (`net/icmp.c`) is echo-only, both halves: it reflects incoming echo
requests for our IP (so the host can ping us) and matches the replies to our own
requests (so we can ping the gateway). The boot self-test pings `10.0.2.2` four
times and reports RTT:

```
[icmp] PING 10.0.2.2 : 4 packets
[icmp] reply from 10.0.2.2: seq=1 time=939 us
[icmp] reply from 10.0.2.2: seq=2 time=203 us
[icmp] reply from 10.0.2.2: seq=3 time=149 us
[icmp] reply from 10.0.2.2: seq=4 time=196 us
[icmp] 4/4 replies received -- PING OK
[net] ipv4 rx_ok=4 rx_drop=0 ...
```

One successful echo validates the whole lower stack in a single round-trip:
Ethernet TX/RX, ARP, IPv4 TX/RX, checksum **both directions**, and ICMP. With
ping working, AuroraOS has crossed from a local desktop OS into a networked one.
