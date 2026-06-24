# AuroraOS — Security & HTTPS Foundation

With the network stack complete through a user-space HTTP client over a clean
socket API, the next foundation is **cryptography → TLS → HTTPS** — the last big
infrastructure barrier before AuroraOS can talk to the modern (HTTPS-only) web.

The discipline here is **known-answer test vectors for every primitive**, checked
in isolation on the build host so a crypto bug can never hide behind the network.
The portable primitives live in `crypto/` (freestanding C — only `<stdint.h>` /
`<stddef.h>`, no allocation, no OS calls) so the same source serves the host
test, user space, and (if ever needed) the kernel.

Run the vectors: `make crypto-test`.

## Roadmap

| Step | Piece | Verified against | Status |
|------|-------|------------------|--------|
| 1 | **SHA-256** (`crypto/sha256.c`) | NIST FIPS 180-4 | ✅ |
| 2 | **HMAC-SHA256** (`crypto/hmac_sha256.c`) | RFC 4231 | ✅ |
| 3 | **HKDF** (Extract/Expand) (`crypto/hkdf.c`) | RFC 5869 | ✅ |
| 4 | **ChaCha20** (`crypto/chacha20.c`) | RFC 8439 | ✅ |
| 5 | **Poly1305** (`crypto/poly1305.c`) | RFC 8439 + OpenSSL | ✅ |
| 5b | **ChaCha20-Poly1305 AEAD** (`crypto/chacha20poly1305.c`) | RFC 8439 §2.8.2 | ✅ |
| 6 | **TLS 1.3 record layer** (`tls/record.c`) | RFC 8446 §5 round-trip | ✅ |
| 7 | **X25519** (ECDHE key exchange) (`crypto/x25519.c`) | RFC 7748 | ✅ |
| 8 | **Transcript hash + key schedule** (`tls/transcript.c`, `tls/key_schedule.c`) | RFC 8448 §3 trace | ✅ |
| 9 | **Handshake messages v1** (`tls/handshake.c`) — ClientHello/ServerHello/Finished | RFC 8446 §4 | ✅ |
| 10 | **Client handshake FSM core** (`tls/client.c`) — event-driven, no network | RFC 8446 §4 / §A.1 | ✅ |
| 11 | **Record binding** (`tls/conn.c`) — phase gating, key switch, reassembly | RFC 8446 §5 | ✅ |
| 11b | **RFC 8448 trace runner** (`tools/tls_trace_test.c`) — engine vs real bytes | RFC 8448 §3 | ✅ |
| 12.1 | **ASN.1 DER reader** (`x509/asn1.c`) — bounds-checked TLV cursor | X.690 / RFC 8448 cert | ✅ |
| 12.2 | **X.509 certificate parser** (`x509/x509.c`) — no crypto | RFC 5280 / RFC 8448 + SAN | ✅ |
| 12.3 | **RSA verification** (`crypto/bignum.c`, `crypto/rsa.c`, `x509/verify_cert.c`) | RFC 8448 cert (self-signed) | ✅ |
| 12.4 | **Trust chain + validity + hostname** (`x509/verify_cert.c`) | synthetic CA→leaf chain | ✅ |
| 12.5 | **Certificate integration** (`tls/cert.c`) — message parse + PKI + FSM | synthetic chain via FSM | ✅ |
| 12.5b | **CertificateVerify** (`crypto/mgf1.c`, `crypto/rsa_pss.c`, `tls/cert.c`) | RFC 8448 CertificateVerify | ✅ |
| 12.6 | **FSM authentication** (`tls/client.c`) — Cert+CV+Finished, `peer_authenticated` | synthetic authed handshake | ✅ |
| 13.0a | **Network audit** (`docs/NET_SEMANTICS.md`) + **record reader** (`tls/record_reader.c`) | host framing tests | ✅ |
| 13.0b.0 | **TCP rx-buffer fix** — compacting receive ring (`net/rxring.c`), `tcp.c` migrated | host ring test (`make rxring-test`) | ✅ |
| 13.0b.1 | **Handshake driver** (`tls/driver.c`) — `transport → reader → conn → CONNECTED` | host driver test (4 chunkings + EOF) | ✅ |
| 13.0b.2a | **IP-literal connect** (`net/tcpsock.c`) — reach a numeric host without DNS | kernel build | ✅ |
| 13.0b.2b | **`tlsconnect`** (`user/tlsconnect.c`) — socket → driver → CONNECTED, embedded root | builds; QEMU run on Aurora side | ✅ code |
| 13.0b.3 | **Application-data smoke test** — send/recv one app record over the live epoch | host app-data test; QEMU echo | ✅ code |
| 13.0b.4 | **Oversized cert chain** — multi-cert, many records, buffer-limit safety | host test | ✅ |
| 13.0c | Real internet RSA endpoint: `GET /` → 200 OK | real `https://` site | later |
| 13.x.1a | **P-256 field** (`crypto/p256_field.c`) — GF(p) add/sub/mul/sqr/inv | host KAT vs Python | ✅ |
| 13.x.1b | **P-256 scalar** (`crypto/p256_scalar.c`) — GF(n), separate ring | host KAT vs Python | ✅ |
| 13.x.2 | **P-256 points** (`crypto/p256_point.c`) — Jacobian add/double/scalar-mul | host KAT: k·G, group invariants, n·G=O | ✅ |
| 13.x.2b | **EC public-key validation** (`p256_pubkey_decode`) — on-curve, bounds, n·Q=O | host: valid + invalid vectors | ✅ |
| 13.x.3 | **ECDSA verify** (`crypto/ecdsa.c`) + strict DER + fast field reduction | **484/484 Wycheproof** | ✅ |
| 13.x.4 | **X.509 ECDSA** — `prime256v1` SPKI + `ecdsa-with-SHA256` in the verify dispatcher | host KAT: cert→PASS, ±TBS→FAIL, ±sig→FAIL | ✅ |
| 13.x.5 | **TLS CertificateVerify** dispatch on SignatureScheme (0x0403) + extensible ClientHello sigalg list | host: RSA/ECDSA ✓, crossed scheme ✗ | ✅ |
| 13.x.6 | **Full ECDSA flight → CONNECTED** (no HTTP) — same FSM, no special branch | host: PASS + forged-CV/forged-Finished rejected | ✅ host |
| **14.0** | **Real Internet HTTPS** — live external sites (Cloudflare/Fastly/GitHub/Let's Encrypt) | real `https://` | next |
| 13.y | Intermediate CA chains (leaf → intermediate → root) | real chains | with 14.0 |

With X25519 done the **cryptographic** toolbox for a TLS 1.3 ChaCha20-Poly1305
client is complete — hash, MAC, HKDF, AEAD, record layer, and now key agreement.
What is left is pure protocol: the key schedule glue, the handshake state
machine, and certificate/signature verification (a later, separable layer).

With AEAD done, the **symmetric** half of TLS 1.3 is essentially complete: hash,
MAC, key schedule (HKDF), stream cipher and authenticated encryption are all
RFC-verified. What remains is protocol logic (record framing, key schedule glue,
handshake state machine) plus the asymmetric pieces (X25519, then certificate /
signature verification) — a separate `tls/` layer over these primitives.

The PKI layer is now under way in `x509/` (ASN.1 DER reader done; X.509 parse,
RSA verification and a minimal trust store to follow). Deliberately still **out of
scope**: ECDSA (added after RSA, since the RFC 8448 reference cert is RSA), full
certificate-chain path building, OCSP/CRL revocation, AIA fetching, name
constraints, and wildcard corner cases — a later hardening pass.

### Planned layering

`crypto/` stays pure primitives, independent of TLS and verifiable on the host.
The protocol lands later in a separate `tls/` tree so TLS-specific glue never
leaks into the primitives:

```
crypto/  sha256  hmac  hkdf  chacha20  poly1305      (RFC-vector tested, no TLS)
   ↓
tls/     hkdf_label  transcript  record  handshake    (TLS protocol)
```

In particular `HKDF-Expand-Label` / `Derive-Secret` are TLS helpers (`tls/`), not
crypto primitives — they wrap `hkdf_expand`, they don't live inside it.

`tls/` has its own host harness: `make tls-test`.

## Step 1–2 — SHA-256 + HMAC-SHA256

`sha256_init/update/final` (+ a one-shot `sha256()`) implement FIPS 180-4;
`hmac_sha256()` is RFC 2104 over it. `make crypto-test` runs:

```
SHA-256 (NIST FIPS 180-4):   "" / "abc" / 56-byte / 1,000,000 x 'a'   -> PASS
HMAC-SHA256 (RFC 4231):      cases 1, 2, 3, 4, 6 (long key)           -> PASS
CRYPTO TEST: ALL PASS
```

HMAC-SHA256 is the workhorse the next steps build on: HKDF (TLS 1.3's entire key
schedule), Poly1305 keying, and token/signature checks.

## Step 3 — HKDF (RFC 5869)

`hkdf_extract(salt, ikm) -> prk` is just `HMAC-SHA256(salt, ikm)` (a zero salt of
`HashLen` bytes when none is given); `hkdf_expand(prk, info, len) -> okm` is the
`T(i) = HMAC(prk, T(i-1) | info | i)` counter loop, truncated to `len`. Both are
freestanding (a single fixed `T(i-1) | info | i` buffer, no allocation). `make
crypto-test` runs all three RFC 5869 SHA-256 vectors (PRK **and** OKM):

```
HKDF-SHA256 (RFC 5869):  case 1 (salt+info) / case 2 (80-byte inputs, 82-byte OKM)
                         / case 3 (no salt, no info)   -> PASS
```

This is the pivot point for TLS 1.3: its key schedule is `HKDF-Extract` plus
`Derive-Secret`/`HKDF-Expand-Label`, both thin wrappers over these two calls, so
the handshake's secret derivation becomes mechanical once the AEAD is in place.

## Step 4 — ChaCha20 (RFC 8439)

ChaCha20 comes before AES on purpose: on i686 there is no AES-NI, ChaCha20 is
simpler and constant-time by construction, and it pairs with Poly1305 into
`TLS_CHACHA20_POLY1305_SHA256` — a complete HTTPS path with no AES at all. The
module is a small three-call API (`chacha20_init` / `chacha20_block` /
`chacha20_xor`), with the quarter-round exposed so the lowest layer is testable
on its own. `make crypto-test` checks all three RFC 8439 levels:

```
ChaCha20 (RFC 8439):  quarter-round (§2.1.1) / state quarter-round (§2.2.1)
                      / 64-byte block keystream (§2.3.2)
                      / 114-byte encryption (§2.4.2)   -> PASS
```

A bug at any level invalidates everything above it, so the quarter-round is
proven first, then the block function, then real XOR encryption end-to-end.

## Step 5 — Poly1305 (RFC 8439)

A pure one-time authenticator: `poly1305_auth(tag, msg, len, key)` — message plus
a one-time 32-byte key → a 16-byte tag, nothing TLS-specific. Arithmetic is mod
2^130-5 in five 26-bit limbs (the "donna-32" representation), so it needs only
32×32→64-bit multiplies and no 128-bit type — fine for plain i686.

Block boundaries are where Poly1305 implementations usually break, so beyond the
canonical RFC §2.5.2 vector the harness checks lengths 0, 1, 15, 16, 17. Those
expected tags come from an **independent** reference (OpenSSL 3's
`openssl mac POLY1305`), not from this code, so they are real known-answer tests:

```
Poly1305 (RFC 8439):  RFC 2.5.2 (34-byte)
                      len 0 / 1 / 15 / 16 / 17  (vs OpenSSL)   -> PASS
```

`len 0` lands on `tag == s == key[16..31]`, confirming the empty-message path.

> **One-time key:** Poly1305 is only secure if each key authenticates exactly one
> message. The AEAD step derives a fresh Poly1305 key per record from ChaCha20.

## Step 5b — ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)

The combined construction TLS 1.3 actually uses (`TLS_CHACHA20_POLY1305_SHA256`):

- `seal(key, nonce, aad, pt) -> ct, tag` — derive a one-time Poly1305 key from
  the ChaCha20 keystream at counter 0 (§2.6), encrypt with counter 1, then MAC
  `aad | pad16 | ct | pad16 | le64(aadlen) | le64(ctlen)`.
- `open(...)` — recompute the tag, compare it in **constant time**, and only then
  decrypt. A bad tag returns `-1` and yields no plaintext.

To MAC several non-contiguous spans without a big buffer (TLS records reach
~16 KB), Poly1305 grew a streaming `init`/`update`/`final` context; the one-shot
`poly1305_auth` is now a thin wrapper, so its KATs are unchanged.

Beyond matching the §2.8.2 vector, the harness checks the security property the
whole TLS record layer rests on — that authentication actually rejects tampering:

```
ChaCha20-Poly1305 AEAD:  seal ct / tag (§2.8.2)   -> match
                         open(valid) -> 0, recovers plaintext
                         flip 1 byte of ciphertext / AAD / tag -> open == -1
```

## Project maturity snapshot (at this milestone)

A rough self-assessment after the AEAD step — the symmetric crypto is no longer
the weak point; TLS/HTTPS now is:

| Subsystem | Maturity |
|-----------|----------|
| Kernel (VM, IPC, SHM, timers) | █████████░ |
| Window manager / compositor | █████████░ |
| Desktop UX (Dock/Finder/Viewer/Settings) | ████████░░ |
| Filesystem | ███████▌░░ |
| Networking (L2–L4, DNS, sockets) | ████████▌░ |
| TCP (retransmit; no RTT est. yet) | ███████▌░░ |
| Crypto — symmetric primitives | █████████░ |
| TLS 1.3 client (handshake + record binding, RFC 8448-verified; no cert trust) | ████████░░ |
| Certificate / X.509 PKI | ░░░░░░░░░░ |
| GPU acceleration | █░░░░░░░░░ |
| x86_64 port | ░░░░░░░░░░ |

The first real internet request from Aurora Fetch hit `426 Upgrade Required` —
the web itself telling Aurora to learn HTTPS. That makes the TLS record layer the
single highest-value next step, which is exactly what step 6 begins.

## Step 6 — TLS 1.3 record layer (RFC 8446 §5)

The crossover from `crypto/` to `tls/`: the first protocol code, pure framing
over the verified AEAD, no networking (bytes in, bytes out).

- `tls_record_seal(type, plaintext) -> TLSCiphertext` builds `TLSInnerPlaintext`
  (`content || real_type`), derives the nonce, and AEAD-seals in place. The
  on-wire `opaque_type` is always `application_data` (23); the real type is
  hidden inside the encryption.
- `tls_record_open(record) -> (type, content)` reconstructs the nonce from its
  own sequence counter, AEAD-opens (verify-before-decrypt), then strips the
  trailing zero padding and the inner type byte.
- **nonce** = `write_iv XOR left-pad(seq, 12)` (§5.3); **AAD** = the 5-byte
  record header (§5.2). The sequence number is implicit state on each side, so a
  reordered or replayed record derives the wrong nonce and fails authentication.

TLS 1.3 publishes no ChaCha20-Poly1305 record KAT, so `make tls-test` pins it
three ways:

```
nonce (§5.3):     iv/seq combinations vs hand-computed values
framing:          record == the verified AEAD invoked manually, byte-for-byte
behaviour:        round-trip recovers (type, content); seq advances; identical
                  plaintext at seq 0 vs 1 differs on the wire; tampered byte ->
                  open == -1; wrong sequence number -> open == -1
```

This is the bridge to the handshake: ServerHello-onward is just records, and
`EncryptedExtensions` / `Finished` are sealed/opened with exactly this code.

## Step 7 — X25519 (RFC 7748)

The last fundamental primitive — Diffie-Hellman on Curve25519. The shared secret
it produces is the input to the TLS 1.3 key schedule (`HKDF-Extract(.., ECDHE)`).

A constant-time Montgomery ladder with branch-free conditional swaps, so the
secret scalar never steers control flow or memory access. Field arithmetic is mod
2^255-19 in 16 limbs of radix 2^16 — 64-bit multiplies only, no 128-bit type,
fine for plain i686. `make crypto-test`:

```
X25519 (RFC 7748):  scalarmult vectors 1 & 2 (§5.2) / iterative 1-iter (§5.2)
                    / §6.1 Diffie-Hellman: Alice & Bob publics, shared secret,
                      and both sides agree   -> PASS
```

The §6.1 case is the real end-to-end check: derive each side's public key from
its secret, then confirm `X25519(a, B) == X25519(b, A)` == the RFC's shared
secret — exactly the exchange the handshake will run.

## Cryptographic toolbox: complete

```
crypto/   sha256  hmac  hkdf  chacha20  poly1305  chacha20poly1305  x25519
tls/      record
```

Every box a TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` client needs for its maths is
now present and RFC-verified. The remaining work is protocol state, not crypto:
key schedule (transcript hash + HKDF-Expand-Label), the handshake messages
(ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify
→ Finished), and certificate/signature validation.

## Step 8 — transcript hash + key schedule (RFC 8446 §7.1)

The deterministic key algebra that turns the ECDHE secret + handshake transcript
into traffic secrets and AEAD keys — pure protocol over the verified primitives.

- `tls/transcript.c`: a running SHA-256 over the handshake messages, with a
  **non-destructive snapshot** (`tls_transcript_hash` copies the context before
  finalizing) because the handshake needs the hash at several points while still
  appending later messages.
- `tls/key_schedule.c`: `tls_hkdf_expand_label` / `tls_derive_secret` (TLS
  helpers over `hkdf_expand`, exactly as the layering note requires — not crypto
  primitives), and `tls_key_schedule_derive` building Early → Handshake → Master
  secrets and the client/server handshake-traffic secrets.

Verified against the **RFC 8448** "Simple 1-RTT Handshake" trace. The schedule
depends only on SHA-256 and the ECDHE secret (not the AEAD), so that trace is an
authoritative reference even though it negotiates AES-128-GCM:

```
key schedule (RFC 8448 §3):  ECDHE secret (derived by our own X25519 from the
                             trace's client priv + server pub)
                             -> early / handshake / master secret
                             -> client & server handshake-traffic secret
                             -> server write key+iv via HKDF-Expand-Label   -> match
```

The chain is end-to-end: our X25519 produces the shared secret, which flows
through the whole schedule to byte-exact agreement with the RFC. What is left is
sequencing — feeding real ClientHello/ServerHello bytes through this code in a
handshake state machine — plus certificate/signature validation.

## Step 9 — handshake messages v1 (RFC 8446 §4)

The deterministic message core, no certificates yet: build ClientHello, parse
ServerHello, and the Finished verify_data. Only the extensions 1-RTT ECDHE needs
(key_share, supported_versions, supported_groups, signature_algorithms, SNI).

- `tls_build_client_hello` serializes a real ClientHello (length-back-patched
  writer) offering `TLS_CHACHA20_POLY1305_SHA256` + an x25519 key_share.
- `tls_parse_server_hello` is bounds-checked, walks the extensions, and pulls out
  the negotiated cipher suite and the server's x25519 key_share.
- `tls_finished_key` / `tls_finished_verify_data` / `tls_check_finished` — the
  Finished danger zone, kept tiny: `finished_key = HKDF-Expand-Label(secret,
  "finished", "", 32)` and `verify_data = HMAC(finished_key, transcript_hash)`,
  checked in constant time. HKDF-Expand-Label is already pinned to RFC 8448 for
  the `key`/`iv` labels, so `finished` is correct by the same code path.

The headline test is a full **loopback handshake** — no hardcoded server, no
network:

```
handshake (loopback):  client builds ClientHello, server builds ServerHello
                       -> ServerHello parses, cipher + key_share extracted
                       -> X25519 agrees on both sides
                       -> client & server derive identical handshake-traffic
                          secrets from transcript(CH||SH)
                       -> Finished verifies; one flipped byte is rejected
```

This is the proof the whole pipeline composes: two independent peers exchange
real handshake bytes and converge on the same keys. What remains is driving it as
an event-driven state machine over the record layer, then certificate trust.

## Step 10 — client handshake FSM core (RFC 8446 §4 / §A.1)

A deterministic, event-driven engine over *plaintext* handshake messages. It owns
the transcript, the key schedule, and a **(state, key_phase) pair kept
deliberately separate** — `state` is which message is expected next, `phase`
(EARLY → HANDSHAKE → APPLICATION) is which traffic keys the record layer should
use. No network, no record layer, no certificate validation (v1); the ephemeral
key and client random are injected, so a given event sequence always replays to
the same bytes.

Three invariants are enforced exactly where TLS implementations usually drift:

- **transcript phasing.** ServerHello is added before deriving the handshake
  secrets (so they bind `Transcript(CH..SH)`); the server Finished is verified
  over `Transcript(CH..CertificateVerify)` *before* it is appended; the client
  Finished and the application secrets are computed over `Transcript(CH..server
  Finished)`. One message out of place and the secrets diverge.
- **key-phase anchors.** Phase flips to HANDSHAKE only at ServerHello and to
  APPLICATION only at the server Finished — never ad hoc.
- **handshake-only progress.** The FSM consumes handshake messages; record/AEAD
  failures are the caller's concern and never advance it.

Verified by a full **deterministic loopback handshake** through the FSM — a test
"server" emits ServerHello + (dummy) EncryptedExtensions/Certificate/
CertificateVerify + a correctly-keyed Finished, and:

```
FSM loopback:  START -> WAIT_SH -> WAIT_EE -> WAIT_CERT -> WAIT_CV
               -> WAIT_FINISHED -> CONNECTED, phase EARLY -> HANDSHAKE -> APPLICATION
   FSM and server agree on the handshake- and application-traffic secrets
   server-side check of the client's emitted Finished passes
   tampered server Finished -> -1 and the FSM enters ERROR
   out-of-order message (EE while WAIT_SH) -> -1
```

Next is binding this to `tls_record_seal/open` (plaintext gating, key switch on
each phase anchor, per-phase sequence numbers), then certificate trust.

## Step 11 — record binding (RFC 8446 §5)

`tls/conn.c` is the layer between raw TLS records and the FSM — the point where
the handshake finally rides the encrypted record layer. It does three things and
nothing else:

- **Plaintext-vs-encrypted gating.** ClientHello and ServerHello are plaintext
  handshake records; everything after ServerHello is an `application_data` record
  opened with the current read keys. The conn decides which based on the FSM's key
  phase, not the record layer.
- **Key switching at the two phase anchors.** ServerHello installs the handshake
  traffic keys; the server Finished installs the application traffic keys. Each
  switch builds a *fresh* record epoch, so its sequence number restarts at 0 — TLS
  1.3 treats a key change as a new encryption epoch (§5.3). The client Finished is
  sealed under the handshake epoch *before* the switch to application keys.
- **Handshake reassembly.** One record may coalesce the whole server flight
  (EncryptedExtensions | Certificate | CertificateVerify | Finished) or split a
  single message across records; the conn buffers bytes and hands the FSM exactly
  one complete message at a time.

The dependency direction is one-way — `conn → { FSM, record layer } → crypto` —
so the record layer never inspects handshake state and the FSM never sees a
record. A direct consequence, and the headline invariant, is that the two failure
modes are reported distinctly: a record-layer (AEAD) failure is a transport error
that leaves the FSM intact, while only a real protocol violation drives it to
ERROR. `make tls-test` proves the whole thing without a socket:

```
record binding:  ClientHello emitted as a plaintext record
                 plaintext ServerHello -> handshake epoch (rx/tx seq reset to 0)
                 ChangeCipherSpec record ignored (middlebox compat)
                 one coalesced encrypted record (EE|Cert|CV|Finished) -> CONNECTED,
                   application epoch installed, client Finished emitted encrypted
                 server opens & verifies the client Finished
                 application data both directions over the application epoch
   invariant:    tampered ciphertext -> ERR_RECORD, FSM untouched (still WAIT_EE)
   invariant:    valid record, bad Finished -> ERR_PROTOCOL, FSM -> ERROR
   reassembly:   a handshake message fragmented across two records reassembles
```

With the FSM now driven over real encrypted records, the only thing standing
between Aurora and a live `https://` server is trust: parsing the Certificate
chain and verifying CertificateVerify — the X.509 / signature layer (step 12),
which `conn.c` deliberately leaves as a blind transcript for now.

## Step 11b — RFC 8448 trace runner (RFC 8448 §3)

Before touching certificates, the whole protocol engine is frozen against an
authoritative reference: `make tls-trace-test` replays RFC 8448's published
"Simple 1-RTT Handshake" and checks **every derived value byte-for-byte** against
the document. The constants are extracted programmatically from the RFC text, not
transcribed by hand, so the test is a real known-answer baseline.

RFC 8448 negotiates `TLS_AES_128_GCM_SHA256`, while our record layer is
ChaCha20-Poly1305, so the trace's *encrypted records* can't be opened by our AEAD
(that would need AES-GCM, which we don't implement). That is fine: the record
layer is already pinned separately (step 6 + step 11), and what this runner
validates is the **cipher-independent protocol engine** on real RFC bytes — the
same operations the FSM / conn perform internally:

```
RFC 8448 trace:  X25519: client/server public keys + ECDHE shared secret
                 ServerHello parses (cipher 0x1301, key_share) from real bytes
                 Transcript-Hash(ClientHello..ServerHello)
                 Early / Handshake / Master + client&server hs-traffic secrets
                 handshake-epoch write key+iv (server & client) via Expand-Label
                 EncryptedExtensions / Certificate / CertificateVerify framing
                 server Finished verify_data        (== RFC, and our checker accepts it)
                 Transcript-Hash(ClientHello..server Finished)
                 client Finished verify_data        (== RFC)
                 client&server application-traffic secrets + write key+iv
   -> 30 byte-exact checks, TLS TRACE: ALL PASS
```

This is the proof the handshake math is RFC-correct independent of the AEAD and of
certificates: both peers' Finished values and the application secrets reproduce
the RFC to the byte. It freezes a regression baseline so the upcoming PKI layer
can be debugged on its own, never confused with a handshake-engine bug.

## Step 12.1 — ASN.1 DER reader (X.690)

The bottom of the X.509 stack, and the start of a new `x509/` layer (PKI is
neither a pure crypto primitive nor TLS protocol, so it gets its own tree; like
`crypto/` and `tls/` it stays out of the kernel build). `x509/asn1.c` is a
deliberately boring, strict DER reader: a cursor walks a caller-owned buffer one
TLV at a time, with no allocation and no global state.

The one invariant that matters: **the cursor can never read past its buffer.**
`asn1_next` validates before it advances and only commits the cursor on success,
so every downstream parser is automatically bounds-safe. DER (not BER) is
enforced — indefinite length, non-minimal length, an oversized length-of-length,
and the high-tag-number form are all rejected, leaving no encoding ambiguity for
a forged signature to exploit. Helpers: `asn1_expect` (tag-checked read, restores
the cursor on mismatch), `asn1_open` (descend into a constructed element),
`asn1_peek_tag` (for OPTIONAL fields), `asn1_oid_equals`, and `asn1_get_uint`
(minimality-checked, rejects negative / oversized).

`make x509-test` covers every accept/reject path on synthetic TLVs, then walks
the **real RFC 8448 server certificate** — the exact DER our TLS client will have
to parse:

```
ASN.1 basics:    INTEGER / OCTET STRING / long-form length / nested SEQUENCE,
                 peek without consume
ASN.1 rejects:   empty / truncated length / length > buffer / indefinite /
                 non-minimal long form / leading-zero length / high-tag form /
                 oversized length-of-length / negative & non-minimal INTEGER
RFC 8448 cert:   Certificate = SEQUENCE{ tbsCertificate, sigAlg, signatureValue },
                 nothing trails it; descend tbs -> [0] version == 2 (v3),
                 serial == 2, sigAlg OID == sha256WithRSAEncryption,
                 validity = two UTCTime, notBefore == 160730012359Z
```

The RFC 8448 certificate is RSA with `sha256WithRSAEncryption`, which is exactly
why the PKI work goes ASN.1 -> X.509 -> RSA before ECDSA: the same published trace
becomes an end-to-end vector all the way to verifying CertificateVerify. Next
(12.2) is the X.509 parser proper — turning these bytes into a `struct x509_cert`
(subject, issuer, validity, SAN, SubjectPublicKeyInfo, signature) with no trust
decisions yet.

## Step 12.2 — X.509 certificate parser (RFC 5280)

`x509/x509.c` turns a DER certificate into a flat `x509_cert` over the
bounds-checked ASN.1 reader — **no cryptography, no trust decision**. Scope is
kept deliberately tight, exactly the fields a TLS client needs:

- Only the **Common Name** is pulled out of the issuer/subject Distinguished
  Names; the rest of the DN is left alone. CN is diagnostic only — hostname
  matching will use SAN.
- **Validity is normalized to Unix time on the spot** (UTCTime / GeneralizedTime,
  'Z' form), so the later expiry check is just `now >= not_before && now <=
  not_after` — no date strings stored.
- **SubjectAltName dNSName** entries are collected now even though the RFC 8448
  cert has none, because that is what real hostname validation matches against.
- `tbsCertificate`, `SubjectPublicKeyInfo`, the public-key bits and the signature
  are captured as raw slices into the caller's buffer (no copies) — precisely
  what RSA verification (12.3) consumes. The signature is over the raw
  TBSCertificate, so that full element (tag+length+value) is captured verbatim.

The reader's boundedness carries up: every field is read through the cursor, so a
truncated or oversized certificate fails cleanly instead of reading out of bounds.

`make x509-test` checks two certificates — the real reference plus a synthetic one
that exercises the path RFC 8448 cannot:

```
RFC 8448 cert:   version v3, serial 2, issuer/subject CN "rsa", RSA public key,
                 SPKI len 162, TBSCertificate len 281, signature len 128 (RSA-1024),
                 sig OID sha256WithRSAEncryption, validity -> Unix
                 (2016-07-30..2026-07-30), no SAN
synthetic SAN:   subject CN "example.com", issuer CN "Test CA", RSA,
                 san_count == 2 -> "example.com", "www.example.com",
                 validity -> Unix (2024-01-01..2034-01-01)
```

The certificate is now structured data; the last missing piece before trust is
proving the signature over `tbsCertificate`. The RFC 8448 cert is RSA, so 12.3 is
RSA PKCS#1 v1.5 verification — and because the whole chain (ASN.1 -> X.509 -> the
captured `tbs`/`spki_key`/`signature` slices) is already pinned to the published
trace, that step closes a real end-to-end PKI test on RFC bytes.

## Step 12.3 — RSA signature verification (RFC 8017) + the first PKI end-to-end

The crypto/x509 boundary is kept clean: the math lives in `crypto/`, the policy
in `x509/`.

- `crypto/bignum.c` — a fixed-size big integer (32-bit limbs, schoolbook multiply,
  binary long division), the simplest thing that can be correct. No Montgomery, no
  allocation; certificate checks run a handful of times, so clarity beats speed.
  Its KATs (add/sub/mul/cmp/shift/mod/modexp, vs Python) come first and alone, so
  an RSA bug is never a hunt across five places.
- `crypto/rsa.c` — verification only: `rsa_public` (public-exponent modexp) and
  `rsa_pkcs1_v15_verify`. The PKCS#1 v1.5 check is **construct-and-compare** (RFC
  8017 §8.2.2): rebuild the expected `00 01 FF..FF 00 || DigestInfo` and compare,
  instead of parsing the recovered block — no room for a forged DigestInfo or
  short padding (the BERserk class of bugs). RSA knows the envelope, not the hash.
- `x509/verify_cert.c` — the policy seam: hash the TBSCertificate, build the DER
  DigestInfo, **dispatch on the signature-algorithm OID**, and call crypto. RSA +
  SHA-256 is implemented; the dispatcher already has an ECDSA slot that returns
  UNSUPPORTED, so adding ECDSA later needs no restructuring. It proves a signature
  only — no chain, validity-window or hostname decision yet.

`make rsa-test` pins the math; `make x509-test` then closes the first real
**end-to-end PKI test on RFC bytes**. The RFC 8448 certificate is self-signed, so
its own SubjectPublicKey verifies its signature:

```
RFC 8448 cert -> parse -> extract SPKI (modulus, exponent)
              -> SHA-256(TBSCertificate) -> build DigestInfo
              -> RSA public op -> compare EM      => OK
   tamper one TBSCertificate byte                 => BAD_SIGNATURE
   ECDSA signature algorithm OID                  => UNSUPPORTED (dispatch)
```

So ASN.1 ✓, X.509 ✓, RSA ✓ — all on the published reference bytes. What is left is
pure policy, much more tractable than what TLS already required: a trust store
(one root, ISRG Root X1), the validity-window check (now a Unix-time range
compare), and hostname matching against SAN.

## Step 12.4 — trust chain + validity + hostname (RFC 5280 / RFC 6125)

With a signature now provable, this is pure trust *policy* on top of it — no new
crypto. All three live in `x509/verify_cert.c`:

- **Trust chain** — `x509_verify_chain(leaf, roots, root_count)`. v1 is depth 1:
  a root is trusted if its public key validates the leaf's signature, which *is*
  the trust relationship. The array interface is already chain-shaped, so
  intermediate CAs and full DN name-chaining slot in later without an API change.
- **Validity window** — `x509_check_validity(cert, now)` is just
  `not_before <= now <= not_after`, the payoff from normalizing dates to Unix time
  back in 12.2. Distinct NOT_YET / EXPIRED results.
- **Hostname** — `x509_check_hostname(cert, host)` matches against SubjectAltName
  dNSName only (CN ignored, as modern clients require), case-insensitively, with a
  leading `*.` wildcard that matches exactly one left-most label.

`make x509-test` builds a synthetic CA→leaf chain with **real** RSA signatures
(the CA signs the leaf) plus a wildcard SAN, the path RFC 8448 can't exercise:

```
trust:     leaf trusted by its CA root            => OK
           leaf against an unrelated root          => UNTRUSTED
           CA verifies itself (self-signed)        => OK
validity:  now in 2026 / 2023 / 2035  => OK / NOT_YET / EXPIRED
hostname:  example.com, www.example.com (exact, case-insensitive)  => match
           *.test.example vs foo.test.example      => match
           vs a.b.test.example, test.example       => no match (one label only)
           evil.com; CN "rsa" is never used        => no match
```

The PKI engine is now complete for RSA: parse, signature, trust, validity,
hostname. What remains is wiring — `tls_verify_server_certificate(chain, host,
now)` chaining signature→trust→validity→hostname into one call (12.5) — and then
ECDSA P-256 (12.6), the last primitive before a real `https://` fetch (13).

## Step 12.5 — Certificate integration (RFC 8446 §4.4.2)

The point where the handshake stops treating the server's certificate as opaque
transcript bytes and starts deciding whether to trust it. `tls/cert.c` has two
concerns and no cryptography of its own:

- **Message parser** — `tls_parse_certificate` walks the Certificate wire message
  (certificate_request_context + a certificate_list of CertificateEntry) with full
  bounds checks and runs each cert_data through the X.509 parser into a
  `tls_cert_chain`.
- **PKI glue** — `tls_verify_certificate_chain` runs the policy on the end-entity
  certificate: `x509_verify_chain` (trusted by a root) + `x509_check_validity`
  (Unix-time window) + `x509_check_hostname` (SAN), returning one `TLS_CERT_*` code.

This proves the **certificate** (this key belongs to host X, vouched for by a
trusted root). It does *not* prove the peer holds the matching private key — that
is CertificateVerify, the next step.

**FSM integration.** A trust store is now optional on the client
(`tls_client_set_trust`). With one installed, WAIT_CERT parses and validates the
Certificate message, and a failure drives the FSM to ERROR — so a certificate
finally affects TLS state instead of being inert transcript bytes:

```
WAIT_CERT --(PKI ok)--> WAIT_CV
          --(PKI fail)-> ERROR
```

With no trust store the certificate stays transcript-only (engine / replay mode),
which keeps the deterministic loopback and RFC 8448 tests unchanged.

`make tls-test` adds, over the synthetic CA→leaf chain wrapped in a real
Certificate message:

```
parse:  Certificate message -> chain.count 1, leaf CN example.com
glue:   trusted+in-window+host match            => TLS_CERT_OK
        wildcard host foo.test.example          => TLS_CERT_OK
        wrong host / expired / untrusted root    => BAD_HOSTNAME / EXPIRED / UNTRUSTED
        truncated message                        => -1
FSM:    trusted certificate    -> WAIT_CV
        hostname mismatch      -> ERROR
        no trust store         -> accepted (transcript-only)
```

What remains for full server authentication is CertificateVerify — the server's
signature over the transcript with the leaf's private key. In RFC 8448 that is
`rsa_pss_rsae_sha256`, a genuinely new primitive (MGF1 + EMSA-PSS), so it gets its
own step (12.5b: `crypto/mgf1.c` + `crypto/rsa_pss.c` with their own vectors)
before the two halves are joined into one `tls_verify_server_certificate` call.

## Step 12.5b — CertificateVerify (RSA-PSS, RFC 8446 §4.4.3)

The last new cryptography, and the step that turns "this certificate is trusted"
into "the peer actually holds the private key." TLS 1.3 signs CertificateVerify
with `rsa_pss_rsae_sha256`, not PKCS#1 v1.5, so two new primitives land in
`crypto/`, each with its own vectors:

- `crypto/mgf1.c` — MGF1-SHA256 (RFC 8017 §B.2.1), checked against an independent
  Python reference.
- `crypto/rsa_pss.c` — `rsa_pss_sha256_verify`, EMSA-PSS verification (RFC 8017
  §9.1.2) with SHA-256 and salt length == hash length. Verify only, no signing.
  Checked against a real PSS signature produced by an independent toy key.

`tls/cert.c` adds the TLS glue: `tls_verify_certificate_verify` builds the signed
content (`0x20`×64 || `"TLS 1.3, server CertificateVerify"` || `0x00` ||
Transcript-Hash(ClientHello..Certificate)), hashes it, and dispatches on the
SignatureScheme — `0x0804` runs RSA-PSS with the leaf's public key; anything else
is UNSUPPORTED (the ECDSA slot for later). The RSAPublicKey parse is shared with
the PKCS#1 path via `x509_rsa_pubkey`.

The headline check is the **real CertificateVerify from RFC 8448**, verified
byte-for-byte by our from-scratch RSA-PSS + MGF1 (`make tls-trace-test`):

```
Transcript-Hash(ClientHello..Certificate) == RFC value
scheme == rsa_pss_rsae_sha256
CertificateVerify verifies under the leaf key   => TLS_CV_OK
tampered signature / wrong transcript           => TLS_CV_BAD
ECDSA scheme                                     => TLS_CV_UNSUPPORTED
```

Both halves of server authentication are now proven on the published trace: the
certificate (RSA-PKCS#1 over TBSCertificate) and the handshake signature (RSA-PSS
over the transcript). What remains is wiring — joining Certificate +
CertificateVerify at WAIT_CV in the FSM into one `tls_verify_server_certificate`
decision (12.6) — and then a real `https://` fetch (13).

## Step 12.6 — FSM authentication (server authentication as a handshake invariant)

The three proven blocks (certificate chain, CertificateVerify, Finished) existed
side by side; this step makes them a single handshake invariant. With a trust
store installed the FSM now drives:

```
WAIT_CERT --Certificate trusted--> WAIT_CV --CertificateVerify ok--> WAIT_FINISHED
          --reject--> ERROR(CERT)          --reject--> ERROR(AUTH)
```

- **CertificateVerify at WAIT_CV.** The transcript is snapshotted *before* the CV
  message is appended, giving exactly Transcript(ClientHello..Certificate) — the
  boundary RFC 8446 §4.4.3 requires. The leaf public key is captured at WAIT_CERT
  (the parsed slices point into that message, which is gone by WAIT_CV).
- **`peer_authenticated`** flips true only on a successful CertificateVerify — not
  after Certificate, not after Finished. It is the one bit that means "the peer
  proved it holds the leaf private key."
- **Error separation.** `tls_error` distinguishes a rejected certificate
  (`TLS_ERR_CERT`), a failed CertificateVerify (`TLS_ERR_AUTH`) and a framing /
  Finished error (`TLS_ERR_PROTOCOL`), so a future live-HTTPS failure is easy to
  localize.

`make tls-test` runs a full authenticated handshake over the synthetic CA→leaf
chain. Because the library is verify-only, the test plays "server" and signs a
**real** CertificateVerify with the leaf private key (RSA-PSS), exactly as it
already computes the server Finished:

```
Certificate -> WAIT_CV (not yet authenticated)
CertificateVerify (real PSS) -> WAIT_FINISHED, peer_authenticated = 1
Finished -> CONNECTED  (CONNECTED implies authenticated)
tampered CV               -> ERROR(AUTH), peer_authenticated = 0
CV over the wrong transcript (CH..SH) -> ERROR(AUTH)   [pins the snapshot boundary]
bad hostname              -> ERROR(CERT) before any CV
```

CONNECTED is now a cryptographically meaningful state: the certificate is trusted,
the hostname matched, the validity window held, the server proved key ownership,
and the Finished verified. The TLS 1.3 client is logically complete for RSA — what
remains is integration with the real internet (step 13: TLS over sockets, a first
HTTPS GET), then intermediate-CA chains and ECDSA.

## Step 13.0 (logging) — handshake tracing

Before any live socket, the handshake gained tracing — because the first real
failures otherwise read as a bare "CONNECT FAILED" with no clue where. `tls/trace.c`
defines **semantic events** (not strings); the FSM and the record layer emit
milestones and failures through a per-connection sink (no globals, no printf in
the freestanding code). A host test installs a sink that records the sequence;
AuroraOS will install one that prints `[TLS] <event>` to the serial log.

```
[TLS] ClientHello sent
[TLS] ServerHello received        [TLS] Handshake keys installed
[TLS] EncryptedExtensions received
[TLS] Certificate received        [TLS] Certificate chain OK
[TLS] CertificateVerify OK        [TLS] Peer authenticated
[TLS] Finished OK                 [TLS] Application keys installed
[TLS] CONNECTED
```

Failures are equally explicit and carry the locus: `Certificate validation FAILED`,
`CertificateVerify FAILED`, `Unsupported SignatureScheme` (with the scheme), or
`Record decrypt FAILED`. `make tls-test` drives a full authenticated handshake with
a recording sink and asserts the exact milestone sequence, and that a tampered
CertificateVerify ends the trace at the AUTH failure.

This is the first piece of step 13: the diagnostics are in place, so when the FSM
is bound to a real TCP socket the trace will pinpoint whichever integration issue
surfaces first (fragmented records, a longer chain, an ECDSA leaf, ...).

## Step 13.0a — network audit + TLS record reader

Going live splits into a written audit and the one genuinely new layer.

**Audit** (`docs/NET_SEMANTICS.md`): the socket layer pinned in writing before any
integration — recv is a blocking byte stream with no partial-read guarantee and an
ambiguous `0` (peer close *or* 10 s idle), send is stop-and-wait, ownership is
copy-in/copy-out, the RX path is pumped only inside a socket syscall, and — the
headline defect — the 8 KiB per-connection receive buffer never compacts, so a
connection can take at most ~8 KiB total and silently drops-yet-ACKs the rest.
That buffer must be fixed before a real handshake (13.0b.0).

**Record reader** (`tls/record_reader.c`): the bottom seam, turning the TCP byte
stream into complete TLS records. Source-agnostic by construction — feed it bytes
from anywhere, pull records out — so the same code serves host tests, recorded
traces, a socket, and a fuzzer. A returned record points into the reader's buffer
and is valid until the next feed; drain with `next()` until it returns 0, then
feed more. `make tls-test` covers the seven framing cases that bite real streams:

```
1 header + body delivered one byte at a time -> one record
2 whole header, then body byte-by-byte
3 two coalesced records in one chunk -> two records
4 a split inside the SECOND record's header
5 zero-length body (a valid 5-byte record)
6 length limit: 2^14+256 accepted, one over -> error
7 truncated stream: need-more + bytes pending (EOF here = truncated, not a record)
```

With framing proven deterministically, 13.0b binds it to a real socket: fix the
rx buffer, then drive a handshake to CONNECTED against a local RSA `s_server`.

## Step 13.0b.0 — TCP receive ring (the transport fix under TLS)

The audit's headline defect, fixed before any live handshake. The old
per-connection buffer used a write cursor (`rx_len`) that reads never rewound, so
a connection could absorb at most one bufferful **over its entire lifetime** and,
once full, advanced `rcv_nxt` over bytes it had dropped — silently ACKing data it
never stored. That is a transport reliability defect, not a TLS issue, so it was
fixed at the transport layer and proven independently of TLS and of QEMU.

Split into two commits so a post-integration regression localises instantly:

- **13.0b.0a — `net/rxring.c`**: a fixed 16 KiB byte ring (`push`/`pop`/`used`/
  `free`). A pure data structure — no TCP, sequence, or window knowledge; the
  accept/drop *policy* stays in the caller. Freestanding (explicit byte copies,
  no `memcpy`) so one source compiles into both the kernel and the host test.
  `make rxring-test` proves FIFO order, partial-pop continuation, refusal to
  overflow, wrap-around ordering, the exact full/empty boundaries, and — the
  point — ~640 KiB flowing through the 16 KiB ring over 10 000 push/pop cycles.
- **13.0b.0b — `net/tcp.c` migration**: `tcp_recv` pops from the ring (freeing
  space) and sends a window update when it reopens a window it had advertised as
  0; `tcp_input` accepts a segment **all-or-nothing** and never advances
  `rcv_nxt` over bytes it didn't store (a non-fitting segment is dropped so the
  peer retransmits once space frees); `rcv_wnd` carries the real free window on
  every segment. 16 KiB sits comfortably above one max wire record (2^14+256)
  and a multi-KiB certificate chain.

Conservative choice: all-or-nothing per segment rather than partial acceptance,
which would need careful `rcv_nxt`/ACK/window recomputation the simple stack
isn't built for yet. QEMU acceptance (run on the Aurora side): a >8 KiB response
keeps arriving past the first 8 KiB, and a slow 32-byte-at-a-time reader against
a flooding sender keeps progressing (window release + buffer reuse).

## Step 13.0b.1 — the handshake driver (off the wire, deterministically)

The top seam that finally connects the byte transport to the engine:

```
transport (socket)  ->  tls_record_reader  ->  tls_conn  ->  CONNECTED
```

`tls/driver.c` is deliberately thin — all the protocol logic already exists below
it (`tls_conn` does record binding / epoch switching / message reassembly;
`tls_record_reader` does framing). The driver only owns the control loop: send the
ClientHello, pull complete records out of the reader, feed each to `tls_conn`, send
back anything it emits (the client Finished), and stop the instant the FSM reaches
CONNECTED. It is **transport-agnostic** — it touches the network only through a
`tls_transport` of `read`/`write` callbacks — so the identical driver runs over a
kernel socket fd and over a host-test mock. Outbound flights go through `send_all`,
which loops over `write` and never assumes a full write (Aurora's `tsk_write` can
report a short count).

Because the transport is a callback, the record-stream handling — the part most
likely to bite on a real server — is proven **deterministically, off the wire**.
`make tls-test` builds one authenticated server flight (real synthetic chain + a
real RSA-PSS CertificateVerify), seals it into wire records the way `s_server`
does (SH plaintext, then EE | Certificate | CertificateVerify | Finished each as
its own encrypted record), and runs the driver to CONNECTED under adversarial
read/write chunkings:

```
all-at-once   five records in a single read            -> CONNECTED + full trace
byte-by-byte  read 1 / write 1                          -> CONNECTED + full trace
split mid-Certificate  a read boundary inside the cert  -> CONNECTED + full trace
partial writes  write() accepts 1 byte at a time        -> output byte-identical
truncated flight (no Finished)                           -> EOF, never "connected"
```

The clean run is checked end to end both ways: the full client milestone trace
(ClientHello sent → … → CONNECTED) fires, and the captured client output is a
valid ClientHello followed by an encrypted Finished that **verifies server-side**
with the client handshake-traffic key. With this, the TLS engine is no longer a
lab test — it drives a real handshake to CONNECTED from nothing but a byte stream.
What remains for 13.0b.2 is purely the socket adapter (fd → `tls_transport`) and a
QEMU run against a local `openssl s_server -tls1_3`.

## Step 13.0b.2 — TLS over a real socket (`tlsconnect`)

The driver finally meets the network. First a written audit of the userspace seam
(`docs/NET_SEMANTICS.md` §8): the program reaches TCP only through `inet_socket` /
`inet_connect` / `read` / `write` / `close`, and every contract subtlety the driver
must honour — `0` = EOF is fatal before CONNECTED, `<0` = error, a short `write`
keeps going — is already handled. The transport adapter is the expected four-liner
(`read`/`write` over the fd).

Two small commits make it runnable:

- **13.0b.2a — IP-literal connect** (`net/tcpsock.c`): `inet_connect` only did DNS,
  so the guest could not address the QEMU host (`10.0.2.2`) where the test server
  runs and which no resolver knows. A dotted-quad host is now used directly; real
  names still fall through to DNS. This splits "where to connect" (an IP) from "who
  to trust" (the certificate name), which is exactly what a local self-signed test
  needs.
- **13.0b.2b — `user/tlsconnect.c`**: `inet_connect` → `tls_driver_handshake` →
  print the milestone trace → exit. Deliberately narrow — no HTTP, no application
  data (that is 13.0b.3). The trust root is **embedded** (`user/tls_test_root.h`,
  generated by `tools/der2c.py` from `test/tls/cert.pem`), so no filesystem is
  involved; the certificate is checked against its SubjectAltName `aurora-test`
  while the TCP connection goes to the given IP. The ~79 KiB of TLS state lives in
  BSS, never on the 16 KiB user stack; RSA/bignum verification peaks well inside it.

The embedded root is verified on the build host through Aurora's *own* X.509 code
before it is ever trusted in QEMU: it parses, validates at the pinned `now`, matches
`aurora-test` (and rejects a wrong name), and its self-signed chain verifies. What I
cannot do here is run QEMU; the live pass belongs to the Aurora side:

```
# host: a throwaway RSA test server matching the embedded root
openssl s_server -accept 4433 -cert test/tls/cert.pem -key test/tls/key.pem -tls1_3
# guest (Aurora shell): connect to the QEMU host
tlsconnect 10.0.2.2 4433
```

Success is not just "CONNECTED" but the whole chain appearing over real TCP —
`ClientHello sent → ServerHello received → Handshake keys installed → Certificate
chain OK → CertificateVerify OK → Finished OK → Application keys installed →
CONNECTED` — with no change to the crypto or the FSM. That is the strongest
integration result in the TLS branch: TCP → TLS 1.3 → X.509 → RSA-PSS, live.

(`test/tls/key.pem` is a throwaway self-signed test key and is intentionally **not**
committed; only the public `cert.pem` and the embedded DER are in the tree.)

## Step 13.0b.3 — application data over the live epoch

CONNECTED only proves the handshake. The harder thing to get right is the *first
protected application record*: it rides a **new encryption epoch** (the application
traffic keys), with its own sequence number restarted at 0 and its own nonce
derivation, and it must interoperate with OpenSSL on app data, not just handshake
messages. So `tlsconnect` continues past CONNECTED: it seals one record
(`tls_conn_send_app`, default `"PING\n"`), then drains replies
(`tls_conn_recv_app`), printing each, until the peer closes or the idle window
elapses. NewSessionTickets — handshake messages OpenSSL sends *inside* app-data
records right after the handshake — are accepted and ignored, so they do not
derail the exchange.

The deterministic proof is in `make tls-test`: after driving to CONNECTED through
the mock transport, the test exchanges application data with the server mirror's
application keys and checks, byte-for-byte:

```
client -> server  record #0 ("PING")   server decrypts
client -> server  record #1             decrypts -> client app tx seq advanced
server -> client  record #0 ("PONG")    client decrypts
server -> client  record #1             decrypts -> client app rx seq advanced
server -> client  NewSessionTicket      accepted, yields no app data
server -> client  tampered record       AEAD rejects -> ERR_RECORD
```

That pins the four things app data can break on independently of the handshake:
the application secrets match end to end, the per-epoch sequence numbers advance in
both directions, the nonce derivation holds, and seal/open round-trip with a real
peer. QEMU acceptance (Aurora side): run the same `s_server`, then `tlsconnect
10.0.2.2 4433` — `PING` appears on the server console, and whatever you type back
there is printed by `tlsconnect` as a decrypted reply. A round-trip means the TLS
channel — not just the handshake — lives over real TCP.

With that, the highest remaining risk for the real web is no longer the handshake
or app data but the **signature scheme**: most sites authenticate with ECDSA
P-256 (`ecdsa_secp256r1_sha256`), which the dispatcher currently answers
UNSUPPORTED. That, not an HTTPS client, is the next major block (13.x).

## Step 13.0b.4 — oversized certificate chain (the next buffer risk)

A local self-signed cert barely exercises reassembly; a real server sends a
multi-cert chain (leaf + intermediate + extensions) of several KB. The previous
buffer defect (`rx_buf`) was found by reasoning about lifetime; this one is found
the same way, before the wire. `make tls-test` now drives a **two-cert** chain
(leaf + CA) sealed into ~20 tiny records, with the transport reads deliberately
misaligned to record boundaries — the worst case for the reader's framing and the
conn's message reassembly at once. It reaches CONNECTED with both certificates
parsed. The companion check is the safety guard: a Certificate message whose
declared length exceeds the reassembly buffer (`TLS_CONN_HS_BUF`) is rejected with
`ERR_CAPACITY` the moment its header is seen — never buffered, never overflowed,
never a silent CONNECTED. So a genuinely large or hostile chain fails closed
rather than corrupting memory.

## Step 13.x.1–13.x.3 — ECDSA P-256 verify (the real-web signature scheme)

RSA got Aurora to CONNECTED, but most of the live web authenticates with ECDSA
P-256 (`ecdsa_secp256r1_sha256`). Built bottom-up as separate, independently
KAT'd pieces so a failure localizes to one layer:

- **13.x.1a/1b — field (mod p) and scalar (mod n) as separate rings**
  (`crypto/p256_field.c`, `crypto/p256_scalar.c`): different moduli, different
  files, each checked against Python vectors over edge values (0/1/p−1/n−1,
  near-2^256), including `a·a⁻¹ ≡ 1` and the range checks verification needs.
- **13.x.2 — points in Jacobian coordinates** (`crypto/p256_point.c`): the
  identity is an explicit infinity flag, not magic coordinates; add/double need no
  inversion (one inversion per scalar-mul, at the end). Tested geometry-first
  (double/add on known points, then group invariants G+O / G+(−G)=O / 2G=G+G /
  3G=2G+G), then 9 independent `k·G` vectors, then **n·G = O** — the order check
  that, alongside the `k·G` vectors, makes a hidden formula bug very unlikely.
- **13.x.2b — public-key validation** (`p256_pubkey_decode`): rejects wrong
  length/prefix, X or Y ≥ p, off-curve points, and (defense in depth) any point
  with n·Q ≠ O. Tested with valid keys and a battery of invalid ones.
- **13.x.3 — ECDSA verify** (`crypto/ecdsa.c`): a strict X9.62 DER parser
  (rejects non-minimal/indefinite lengths, trailing bytes, negative/zero-padded
  integers, over-long magnitudes) feeding the `s⁻¹` / `u1·G + u2·Q` /
  `x_R ≟ r mod n` equation. Validated against the **official Google Wycheproof
  set — all 484 vectors pass** (174 valid accepted, 310 invalid rejected),
  covering exactly the edges that break ECDSA implementations: r/s = 0 or ≥ n,
  modified hash/signature, malformed DER, leading zeros, edge values near n.

This is the ECDSA analogue of RFC 8448 for the handshake: the negative Wycheproof
cases are the real test. The work is verify-only and uses public data, so nothing
is constant-time.

**Performance note (optimization pulled forward).** The field was first written
on the verified `bignum` (correct but slow): one verify measured ~675 ms, so the
484-vector Wycheproof run took ~5.5 min — too slow to be a routine test, and
borderline for a live handshake. So the fast field reduction the roadmap deferred
was brought forward: P-256's prime lets `value = low + high·2^256` reduce as
`low + high·R0` with R0 = 2^224−2^192−2^96+1, and since 224/192/96 are whole
32-bit words the folds are word-aligned shifts with no bit-twiddling, staying
non-negative so the loop converges to one final subtract. Same `fe` API, so the
13.x.1a KATs and all 484 Wycheproof vectors re-validate it unchanged: verify
dropped to ~17 ms and the full suite to ~8 s. The scalar ring stays on `bignum`
(a handful of ops per verify); a fast mod-n is a later, optional step.

## Step 13.x.4 — ECDSA in the X.509 seam

With the curve math proven, the remaining risk moved out of cryptography and into
the ASN.1/X.509 join: `SPKI → 04‖X‖Y → validate → ecdsa_verify`. Two small wires:

- **Parse-time named-curve check** (`x509/x509.c`): an EC `SubjectPublicKeyInfo`
  is only classified `X509_PK_EC` when the AlgorithmIdentifier carries
  `id-ecPublicKey` **and** the `prime256v1` (P-256) parameters OID. A key on any
  other curve is left `UNKNOWN` rather than letting a non-P-256 point reach the
  P-256 verifier. For an EC key the BIT STRING contents are already the
  uncompressed point `0x04‖X‖Y`, i.e. exactly `ecdsa_p256_verify`'s `pub`.
- **Dispatcher branch** (`x509/verify_cert.c`): the `ecdsa-with-SHA256` OID, which
  previously returned `UNSUPPORTED`, now hashes the TBSCertificate and calls
  `ecdsa_p256_verify(issuer_key, SHA-256(tbs), signature)`. The verifier fully
  re-validates the key (length/prefix, coords < p, on-curve, subgroup) and parses
  the signature strictly, so a spoofed `sig_oid` pointing an ECDSA algorithm at a
  non-EC key fails the key decode instead of being trusted.

Validated with a real `openssl`-generated ECDSA P-256 cert
(`test/tls/ec_cert.pem`, embedded in the host test) against the three KATs the
plan called for:

| KAT | input | result |
|-----|-------|--------|
| #1 | unmodified self-signed cert | **PASS** (and trusts itself via `x509_verify_chain`) |
| #2 | one byte flipped in TBSCertificate | **FAIL** (`BAD_SIGNATURE`) — proves the body is actually hashed, not just parsed |
| #3 | one byte flipped in the signature | **FAIL** (`BAD_SIGNATURE`) — exercises the dispatcher + DER signature path |

After this, `RSA certificates PASS` and `ECDSA certificates PASS`. The kernel
image is untouched (x509/ is outside its source set); the userspace HTTPS client
(`tlsconnect.elf`) now links the ECDSA/P-256 objects via `verify_cert.c`. ECDSA is
**not yet** wired into the TLS CertificateVerify handler or advertised in the
ClientHello `signature_algorithms` — that is 13.x.5, and until then a server will
still pick RSA or abort. The throwaway EC private key (`test/tls/ec_key.pem`) is
gitignored, like the RSA test key.

## Step 13.x.5 — ECDSA in the TLS CertificateVerify seam

The certificate chain proves *whose* key it is; CertificateVerify proves the peer
*holds* that key, by signing the handshake transcript. Two wires, governed by two
invariants:

- **Dispatch on the SignatureScheme, not the certificate key type**
  (`tls/cert.c`). The signed content (`0x20`×64 ‖ context ‖ `0x00` ‖
  transcript-hash) is built once, then a `switch (sig_scheme)` routes to
  `rsa_pss_rsae_sha256` or `ecdsa_secp256r1_sha256`. TLS authenticates the
  *signature*, whose algorithm is named in the message — so the message is the
  source of truth, and a scheme/key mismatch fails inside the per-scheme verifier
  rather than being silently accepted.
- **One extensible advertised list** (`tls/handshake.c`). The ClientHello
  `signature_algorithms` extension is emitted from a single
  `static const uint16_t tls_sigalgs[]` (ECDSA-P256, RSA-PSS, RSA-PKCS1), so
  adding a scheme later is one line, not edits scattered across the writer. The
  SignatureScheme code points live in one header (`tls/cert.h`).

The 2×2 dispatch matrix is the test that matters — crossed scheme/key is exactly
where a dispatcher keyed on the wrong thing breaks:

| signature | scheme announced | result |
|-----------|------------------|--------|
| RSA-PSS, RSA key | `rsa_pss_rsae_sha256` | **OK** |
| ECDSA, EC key | `ecdsa_secp256r1_sha256` | **OK** |
| RSA-PSS, RSA key | `ecdsa_secp256r1_sha256` | **BAD** — RSA key isn't a P-256 point |
| ECDSA, EC key | `rsa_pss_rsae_sha256` | **MALFORMED** — EC point isn't an RSAPublicKey |

Both PASS cases use real signatures over a fixed transcript hash (RSA-PSS signed
in-test, ECDSA signed by `openssl dgst -sha256 -sign` with `ec_key.pem`); tamper
and wrong-transcript variants reject, and an unimplemented scheme (ed25519) still
returns `UNSUPPORTED`. The RFC 8448 trace test's old "ECDSA → UNSUPPORTED" check
now correctly reads "RSA key under ECDSA scheme → BAD".

After this the client can verify **both** an RSA and an ECDSA CertificateVerify
and advertises both, so cryptographically it understands most modern servers.
What remains before a real site is 13.x.6: prove a full ECDSA server flight
(Certificate + CertificateVerify + Finished) drives the existing FSM/driver to
CONNECTED with no special-case branch.

## Step 13.x.6 — full ECDSA flight reaches CONNECTED

The proof that the two new seams (X.509 ECDSA, ECDSA CertificateVerify) actually
compose: a complete server flight — EncryptedExtensions, an EC Certificate, an
ECDSA CertificateVerify, and Finished — is fed through the **same** `tls_client`
FSM that handles RSA, and it reaches CONNECTED. The FSM has no `if (ecdsa)`
branch; it dispatches on the certificate's algorithm and the CertificateVerify's
SignatureScheme, so the ECDSA path is just data flowing through the RSA machinery.
One flight exercises both 13.x.4 (the self-signed EC cert verifies as its own
trust root) and 13.x.5 (the ECDSA CertificateVerify over the live transcript).

Scope is deliberately narrow — no HTTP, no GET, no application data, no external
network, no OpenSSL. Just: does the handshake authenticate and connect?

- **PASS:** Certificate → WAIT_CV → CertificateVerify → WAIT_FINISHED
  (`peer_authenticated` set) → Finished → CONNECTED.
- **Test A (forged CertificateVerify):** flip a signature byte → `FAIL_AUTH`,
  never CONNECTED, `peer_authenticated` stays 0.
- **Test B (forged Finished):** valid CV, then flip a Finished byte → rejected,
  never CONNECTED. A bad Finished is an integrity failure (`TLS_ERR_PROTOCOL`),
  classified separately from CertificateVerify's peer-auth failure
  (`TLS_ERR_AUTH`); `peer_authenticated` was already set by the valid CV, which is
  correct — the peer *did* prove key possession; the transcript MAC is what broke.

**Test-only ECDSA signer.** Producing a CertificateVerify over the *live*
transcript (rather than fragile pre-recorded bytes) needs a signer; the library
is verify-only by design, so this lives in the test harness as `ecdsa_sign_for_test`
— the exact analogue of the existing RSA `pss_sign_cv`. It is a testing tool, not
a new TLS-client capability: nothing is added to `crypto/`. It signs with a
SEPARATE throwaway EC key (`test/ec_test_key.pem`, gitignored; the cert DER and
private scalar are embedded as constants in the test, like the RSA `T_LEAF_*`
pair). That key is never used in QEMU, `openssl s_server`, the trust store, or any
live certificate — production secrets ≠ test secrets.

With this, FSM authentication is proven on both paths (RSA and ECDSA) with no
special-casing. The remaining risk is no longer in the cryptography but in real
certificate chains, intermediate CAs, chain sizes, HTTP/1.1, and live-server
behavior — a different class of problem, which is **Phase 14.0 (Real Internet
HTTPS)**.
