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
| 10 | Handshake state machine + record integration | RFC 8446 §4 | next |
| 11 | Certificate / signature validation | RFC 8446 §4.4 | later |
| 12 | HTTPS GET in Aurora Fetch | real `https://` site | later |

With X25519 done the **cryptographic** toolbox for a TLS 1.3 ChaCha20-Poly1305
client is complete — hash, MAC, HKDF, AEAD, record layer, and now key agreement.
What is left is pure protocol: the key schedule glue, the handshake state
machine, and certificate/signature verification (a later, separable layer).

With AEAD done, the **symmetric** half of TLS 1.3 is essentially complete: hash,
MAC, key schedule (HKDF), stream cipher and authenticated encryption are all
RFC-verified. What remains is protocol logic (record framing, key schedule glue,
handshake state machine) plus the asymmetric pieces (X25519, then certificate /
signature verification) — a separate `tls/` layer over these primitives.

Deliberately **out of scope for now**: X.509 / ASN.1 parsing, RSA, ECDSA,
certificate-chain validation. Those are a separate layer; the symmetric
primitives + key schedule + record layer come first.

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
| TLS / HTTPS | ░░░░░░░░░░ |
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
