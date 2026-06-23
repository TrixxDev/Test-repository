/* ECDSA signature verification on NIST P-256 with SHA-256 (verify-only).
 *
 * Ties together the field, scalar, and point modules into the X9.62 / RFC 6979
 * verification equation. The signature is its X9.62 DER form (SEQUENCE{r,s}); a
 * strict parser lives here because that encoding is intrinsic to the algorithm,
 * and Wycheproof exercises exactly its edges (leading zeros, non-minimal lengths,
 * trailing bytes, r/s = 0 or >= n). The public key is validated before use.
 * Verify-only, public data, so nothing is constant-time. Freestanding. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Verify an ECDSA-P256-SHA256 signature. `pub` is the uncompressed public key
 * 0x04 || X || Y (65 bytes); `hash` is the 32-byte message digest; `sig_der` is
 * the DER-encoded ECDSA-Sig-Value. Returns 0 iff the key is valid, the signature
 * parses strictly, and the verification equation holds; -1 otherwise. */
int ecdsa_p256_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t hash[32],
                      const uint8_t *sig_der, size_t sig_len);

/* Parse a strict X9.62 DER ECDSA-Sig-Value into 32-byte big-endian r and s.
 * Returns 0 on a well-formed encoding, -1 otherwise. Exposed for reuse by the
 * X.509 ECDSA signature path. */
int ecdsa_sig_from_der(const uint8_t *der, size_t len, uint8_t r[32], uint8_t s[32]);
