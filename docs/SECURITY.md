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
| 4 | ChaCha20 | RFC 8439 | next |
| 5 | Poly1305 → ChaCha20-Poly1305 AEAD | RFC 8439 | later |
| 6 | TLS record layer (encrypt/decrypt, no handshake) | local round-trip | later |
| 7 | TLS 1.3 client handshake → HTTPS GET | real `https://` site | later |

Deliberately **out of scope for now**: X.509 / ASN.1 parsing, RSA, ECDSA,
certificate-chain validation. Those are a separate layer; the symmetric
primitives + key schedule + record layer come first.

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
