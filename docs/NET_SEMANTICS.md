# AuroraOS — Network Semantics (TLS-over-sockets audit)

Written **before** binding the TLS engine to a real socket (Phase 13.0a). The TLS
state machine is deterministic; the transport under it is not. This document pins
the exact behaviour of Aurora's socket layer so the integration code is written
against what the stack *actually does*, not against POSIX assumptions — and so the
record-reassembly / framing boundaries are explicit rather than discovered as
"random AUTH failures" later.

Sources audited: `net/tcp.c`, `net/tcpsock.c`, `net/net.c`, `user/libc.h`,
`user/libc/net.c`, `user/libc/http.c`, `user/fetch.c`.

## 1. The three stream models (the load-bearing distinction)

| Layer | Model | Boundary owner |
|-------|-------|----------------|
| TCP (`tcp_recv`) | **byte stream** — arbitrary chunks, no message boundaries | — |
| TLS record | **framed** — 5-byte header + `length`, one TLSCiphertext at a time | new reader (13.0a) |
| TLS FSM (`tls_conn`) | **message** — one handshake message at a time | `tls/conn.c` (done) |

These must not be conflated. `tls_conn_recv_record()` already requires a *complete*
record; `tls_conn`'s `hs_buf` already reassembles handshake messages out of
decrypted records. What is missing is the **bottom** seam: turning the TCP byte
stream into complete TLS records. That is the one genuinely new piece of glue in
13.0a — everything above it is already proven on the host.

## 2. I/O abstraction

The userspace API is just VFS read/write on a socket fd (`user/libc.h`):
`send == write(SYS_WRITE)`, `recv == read(SYS_READ)`. The backend is
`net/tcpsock.c` (`tsk_read`/`tsk_write`).

### recv (`tsk_read`, `net/tcpsock.c:73`)
- **Blocking, busy-poll.** Enables interrupts (`sti`), then loops `net_poll()` +
  `tcp_recv()` until data arrives, the peer closes, or a **10 s idle timeout**.
- **No partial-read guarantee.** Returns `1 .. size` — *whatever is currently in
  the receive buffer*, capped at `size` (`tcp_recv`, `net/tcp.c:207`). One `recv`
  may return part of a TLS record, exactly one, or several coalesced. **Record
  framing is mandatory.**
- **EOF is ambiguous.** Returns `0` on *both* a drained peer-close **and** the
  10 s idle timeout (`net/tcpsock.c:88-91`). Mid-handshake, either is fatal — treat
  `0` as "connection died", never as "try again".
- **No `EAGAIN` / non-blocking mode.** It only ever blocks or returns data/EOF.

### send (`tsk_write`, `net/tcpsock.c:97`)
- **Blocking, stop-and-wait.** Splits into ≤ MSS (1400 B) segments and waits for
  each ACK (`tcp_tx_idle`) before the next, with a 4 s per-segment deadline.
- Returns total bytes sent (loops until the whole buffer is sent) or `-1`. A short
  return (`< n`) happens only on a mid-buffer send error — handle it defensively.
- `tcp_send` itself sends **one** segment and truncates `len` to 1400
  (`net/tcp.c:194`); the loop in `tsk_write` is what makes a large `write` whole.

### connect (`tcpsock_connect`, `net/tcpsock.c:37`)
- DNS resolve → `tcp_connect` (SYN) → busy-poll until `ESTABLISHED` or a **5 s**
  deadline. Returns `0`, `-2` (DNS), `-3` (connect/refused).

## 3. Ownership model

**Copy-in / copy-out, no zero-copy, no lifetime entanglement.**
- recv copies kernel `rx_buf → user buf` (`memcpy` in `tcp_recv`).
- send copies `user buf → kernel` segment + the 1-segment retransmit cache
  (`tcp_xmit_track`, `net/tcp.c:157`).
- The user fully owns its buffers before and after each call; the kernel keeps no
  pointer into them. TLS record buffers can therefore live entirely in the TLS
  layer with no aliasing concerns.

## 4. Event-loop model

- **Synchronous RX pump.** `net_poll()` (`net/net.c:32`) drains *all* pending NIC
  frames into the stack, then runs `tcp_tick()`. There is **no background network
  thread**: the RX path is pumped only by whoever is spinning in a blocking
  socket syscall. For a request/response client (always either sending or
  receiving) this is fine; nothing arrives while no one is in a socket call.
- **Preemption via the timer.** The blocking loops run with interrupts on, so the
  100 Hz PIT preempts to other processes. The window server keeps compositing
  while an app blocks in `recv` — but the **blocking app freezes its own UI** for
  the duration (it is stuck in the syscall; see `do_fetch`, `user/fetch.c:149`,
  "shown while the syscall blocks").
- **`poll()` exists** (`SYS_POLL`) but is used for loopback/IPC readiness, not
  wired to TCP sockets. The TLS driver should use plain blocking read/write, like
  `http_get` (`user/libc/http.c`).

## 5. Stream guarantees & limits

- **In-order only.** `tcp_input` accepts data only when `seq == rcv_nxt`
  (`net/tcp.c:411`); out-of-order segments are **dropped** (not buffered). We rely
  on the peer retransmitting in order. SLIRP/local delivery is effectively
  in-order; the real internet is riskier (reordering can stall a fetch).
- **Our TX is retransmitted** (single-segment RTO cache, `net/tcp.c:252`); their
  loss is recovered by us not ACKing the gap.
- **Peer window ignored.** `snd_wnd` is read but not used to gate sending; bounded
  in practice by stop-and-wait (one outstanding segment).

## 6. ⚠ Blockers & risks for TLS (ranked)

### (A) 8 KiB receive buffer that never compacts — ✅ **FIXED (Phase 13.0b.0)**
> Resolved in 13.0b.0a (`net/rxring.c`, a 16 KiB compacting ring with a host
> test) + 13.0b.0b (`net/tcp.c` migrated onto it). `tcp_recv` now frees ring
> space as it drains; `tcp_input` accepts a segment **all-or-nothing** and never
> advances `rcv_nxt` over bytes it didn't store; `rcv_wnd` advertises the true
> free space and a window update is sent when a previously-closed window reopens.
> The original defect is recorded below for context.

The original (pre-fix) code: `struct conn.rx_buf[TCP_RX_CAP=8192]` was **linear
and non-compacting** (`net/tcp.c:52,411`):
```c
unsigned space = (c->rx_len < TCP_RX_CAP) ? TCP_RX_CAP - c->rx_len : 0;  /* uses the WRITE cursor */
unsigned n = plen < space ? plen : space;
memcpy(c->rx_buf + c->rx_len, payload, n);
c->rx_len     += n;       /* only the bytes that fit */
c->tcb.rcv_nxt += plen;   /* but the FULL segment is ACKed */
```
`rx_len` is the monotonic write cursor; `rx_read` (advanced by `tcp_recv`) never
frees space. Consequences:
1. A connection can receive **at most 8192 bytes total, ever** — draining does not
   help.
2. Once full, overflow bytes are **silently dropped yet ACKed** (`rcv_nxt += plen`),
   so the peer believes they were delivered → silent truncation, not an error.

For TLS this is the #1 hazard: a real ServerHello..Finished flight with a full
certificate chain (leaf + intermediates, RSA) routinely exceeds 8 KB, and any HTTP
response body certainly does. A single TLS record alone can be up to ~16.6 KB.

**Fix as implemented (13.0b.0):** `rx_buf` replaced by a 16 KiB ring (`rxring`);
`free = RX_RING_CAP - used` reuses drained space, so a connection streams
arbitrarily large data (the record reader reassembles across reads). A segment
that does not fit whole is **dropped without advancing `rcv_nxt`** (the peer
retransmits once the window reopens — never silently ACKed and lost). `rcv_wnd`
carries the real free window on every segment, and `tcp_recv` emits a window
update when it reopens a window it had advertised as 0. **Conservative choice:**
all-or-nothing per segment, not partial acceptance — partial accept would require
careful `rcv_nxt`/ACK/window recomputation the simple stack isn't built for yet.

### (B) recv EOF/timeout ambiguity
`0` means peer-closed **or** 10 s idle. The TLS driver must treat any `0` before
`CONNECTED` (and any `0` with a partial record buffered) as a hard failure and
emit a trace event, never retry silently.

### (C) RX only flows during a socket syscall
No background pump. The driver must stay in a read loop across the whole server
flight; it cannot, say, do GUI work and expect records to accumulate meanwhile.

### (D) Large `write` is stop-and-wait
One segment per RTT. The ClientHello (~300 B) and client Finished/`GET` (tens of
bytes) are single segments, so handshake latency is unaffected; only large request
bodies (we have none) would feel it.

## 7. Where TLS plugs in

TLS belongs in **userspace**, over the socket fd — `tcpsock.h` already calls itself
"the clean boundary … TLS sits on top of". The `crypto/`, `x509/`, `tls/` trees are
freestanding (`<stdint.h>`/`<stddef.h>` only), so they compile under the userspace
`UCFLAGS`. Plan:

```
inet_socket() / inet_connect(host, 443)
        │  byte stream (read/write)
        ▼
tls record reader        ← NEW (13.0a): accumulate bytes, yield one full record
        │  complete TLSCiphertext
        ▼
tls_conn_recv_record() / tls_conn_send_app()   ← done
        │  handshake messages / app data
        ▼
tls_client FSM + trace   ← done
```
- A `tls_conn` is ~42 KiB (32 KiB `hs_buf` + ~10 KiB client); allocate on the heap
  (`malloc`), not the stack.
- Install the trace sink (Phase 13.0 logging) to print `[TLS] …` to the serial log
  so the first live failures are localizable.
- Build: add the `crypto/ x509/ tls/` objects to the user link for the program that
  fetches (a TLS libc module, then Aurora Fetch on port 443).

## 8. Userspace socket seam — the INET fd contract (audit for 13.0b.2)

Section 5 audited the kernel transport (`tcp.c`/`tcpsock.c`). The TLS program is in
**userspace** and reaches that transport only through syscalls, a different and
narrower contract. There are two unrelated socket worlds; the TLS driver uses the
second:

- `socket(AF_LOOPBACK,…)` + libc `connect(fd,port)` → **netd** RPC over message IPC
  (`kernel/socket.c`, `user/libc/net.c`): in-process loopback rings, *not* TCP/IP.
- `inet_socket()` + `inet_connect(fd,host,port)` → **real TCP/IP** (`net/tcpsock.c`).
  This is the path `http_get()` uses and the one `tls_transport` wraps.

The seam is exactly four calls — `inet_socket`, `inet_connect`, `read`/`write`,
`close` (`user/libc.h`). Answers to the audit questions:

1. **fd ownership.** Per-process fd table (`process_t.fds[MAX_FDS]`,
   `kernel/process.c:324`). `inet_socket()` installs a `tcpsock` VFS node
   (`sys_socket` → `tcpsock_create`, `process.c:653`) and returns its fd; the
   process owns it. `close(fd)` unrefs and clears the slot (`sys_close`,
   `process.c:362`) → `tcpsock_close` (FIN + ≤1.5 s drain). fds are inherited on
   `fork` (irrelevant to a single-process `tlsconnect`).
2. **connect timeout.** `inet_connect` → `sys_inet_connect` (`process.c:669`) →
   `tcpsock_connect`: DNS first (**−2** on failure), then `tcp_connect` and a busy
   **5 s** deadline polling for ESTABLISHED, returning **0** / **−3** (timeout or
   refused). It blocks up to ~5 s.
3. **read() return values.** `sys_read` (`process.c:324`) returns **−1** for a bad
   fd, an fd not opened for reading, or an invalid user buffer; otherwise it returns
   `tsk_read`: **>0** bytes, or **0** for EOF. So beyond EOF, the only negative is
   −1 (a hard error). No partial-read *guarantee*: `read` returns whatever is
   available (≥1 byte once data arrives), not a filled buffer — fine, the record
   reader reassembles across reads.
4. **EINTR / EAGAIN.** None. INET `read`/`write` are blocking; there is no
   non-blocking mode (`poll()` is not wired to TCP, §5), no `EAGAIN`, and Aurora has
   no signals, so no `EINTR`. A read blocks (interrupts on, busy-polling `net_poll`)
   until data, EOF, or the 10 s idle timeout.
5. **close() during a blocking recv.** Not a supported concurrency: `tsk_read`
   busy-polls rather than `thread_block`-ing on the socket, and unlike the loopback
   `sock_node` it has no peer-wait/wake to interrupt. `tlsconnect` is single-threaded
   and sequential, so a read is never racing a `close` of the same fd — treat
   cross-thread close-during-read as undefined and simply do not do it.
6. **write() sizes.** `tsk_write` (`net/tcpsock.c:97`) splits into `TCPSOCK_MSS`
   (1400 B) segments, **stop-and-wait** (one ACK per segment, ~4 s budget each), and
   returns the total sent — or a **short count** if a segment fails mid-flight
   (`return sent ? sent : -1`). Any size is accepted; the driver's `send_all` already
   loops on a short return, which is exactly why it exists.

Consequence for the transport adapter: it is the trivial four-liner
`read`/`write`-over-fd, and the only contract subtlety the driver must honour —
`0` = EOF is fatal before CONNECTED (§6 B), `<0` = error, short `write` = keep
going — is already handled.

## 8. Phasing decision (confirmed)

```
13.0a  this audit + the TLS record reader (byte-stream → records), host-tested
13.0b  local RSA TLS server: handshake → CONNECTED over a real TCP socket
       (+ land the rx-buffer compaction fix)
13.0c  real internet RSA endpoint: GET / → 200 OK
```
Integration correctness (record reassembly, partial reads, EOF handling) is
validated against the controlled local server first; the public internet is added
only once the byte-stream → record seam is proven robust.
