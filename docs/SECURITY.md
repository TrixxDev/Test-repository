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
| 13 | TLS over sockets + first HTTPS GET | real `https://` site | next |
| 13.x | Intermediate CAs, then ECDSA P-256 | real chains / wycheproof | later |

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
