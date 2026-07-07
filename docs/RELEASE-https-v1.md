# Aurora HTTPS Stack v1 — milestone

**Aurora can fetch an HTTPS page from the network entirely through its own
networking, cryptography and PKI — and this is demonstrated inside QEMU with full
certificate validation enabled.** Every layer below is written from scratch
(freestanding C, no external libraries) and verified.

This file pins the state at tag `https-v1`. The next series (15.1, trust-store
expansion, and web-compatibility features) builds on top of it.

## Capability checklist

| Layer | Component | Status |
|---|---|---|
| Link | Ethernet, ARP | ✓ |
| Network | IPv4, ICMP | ✓ |
| Transport | TCP (connect/retransmit/teardown), UDP | ✓ |
| Name | DNS (A) | ✓ |
| Crypto — hash | SHA-256, SHA-384/512 | ✓ |
| Crypto — MAC/KDF | HMAC-SHA256, HKDF | ✓ |
| Crypto — AEAD | ChaCha20-Poly1305 | ✓ |
| Crypto — KEX | X25519 | ✓ |
| Crypto — sign verify | RSA PKCS#1v1.5, RSA-PSS, ECDSA P-256, ECDSA P-384 | ✓ |
| TLS | TLS 1.3 client (RFC 8446): handshake, key schedule, record layer | ✓ |
| TLS auth | CertificateVerify (rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384) | ✓ |
| PKI | X.509 parse, depth-N path building, basicConstraints, keyUsage | ✓ |
| PKI policy | validity window, hostname (SAN + wildcard) | ✓ |
| App | HTTP/1.1 GET, de-chunk / Content-Length | ✓ |
| Userspace | `httpsget <host> [path]` over Aurora's own stack | ✓ |
| Proof | secure HTTPS 200 in QEMU, validation ON | ✓ |

Constraints (deliberate v1 scope): TLS 1.3 only; ChaCha20-Poly1305 only; X25519
only; ECDSA up to P-384 (no P-521); HTTP GET only (no redirects / keep-alive /
compression / HTTP/2); no session resumption / ALPN; trust store is a 5-root
starter set (15.1 expands it); no wall clock (validity instant is a build-time
constant). None of these are architectural gaps — they are scope.

## Memory (Phase 15.0, measured on i686)

| Metric | Before | After |
|---|---|---|
| `sizeof(x509_cert)` | 2408 B | **184 B** (−92%) |
| `sizeof(tls_cert_chain)` | ~9.6 KiB (4×2408) | **1108 B** (6×184) |
| `TLS_MAX_CHAIN` | 4 | 6 |
| `httpsget` BSS | ~147 KiB | **~104 KiB** |

15.0.4 analysis confirmed the two large TLS buffers are **correctly sized, not
over-provisioned**: `tls_conn.hs_buf` (2×16 KiB) is genuinely needed for a deep
RSA-4096 chain plus an in-flight record, and the record reader's buffer is the
hard RFC floor (one full 16 KiB wire record) plus a feed margin. They were
documented rather than shrunk — robustness over cosmetic numbers.

## How it is proven

Deterministic host tests (no QEMU): `make crypto-test rsa-test p256-test
p384-test ecdsa-test ecdsa384-test x509-test tls-test tls-trace-test rxring-test`.
Highlights:

- **ECDSA P-256:** 484/484 Google Wycheproof vectors.
- **ECDSA P-384:** 504/504 Google Wycheproof vectors.
- **TLS key schedule / handshake:** RFC 8448 trace replayed byte-for-byte.
- **X.509:** depth-N path building, CA constraints, hostname, real Let's Encrypt
  chain offline, plus a controlled RSA/P-256/P-384 chain.

In-QEMU end-to-end (the headline): `python3 tools/securehttps_qemu.py` generates a
fresh Root→Intermediate→Leaf PKI for each key type, installs the test root in
Aurora's trust store, serves the chain from a local TLS 1.3 server over SLIRP, and
runs `httpsget 10.0.2.2 /` in QEMU. For **RSA, ECDSA P-256 and ECDSA P-384** it
reaches *Certificate chain OK → CertificateVerify OK → Peer authenticated →
CONNECTED → HTTP 200* — validation ON, depth-N, hostname checked — **3/3 PASS**.
No private keys are committed; the production trust store is restored on exit.

Build note: header dependencies are tracked (`-MMD -MP`), so a header edit
rebuilds every dependent object (a stale-object hazard found and fixed during
15.0). The kernel image is never relinked by crypto/TLS/X.509/userspace changes
(the additive invariant), keeping each layer independently verifiable.
