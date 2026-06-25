/* ECDSA signature verification on NIST P-384 with SHA-384 (verify-only).
 *
 * The P-384 analogue of ecdsa.* (P-256/SHA-256): same X9.62 / RFC 6979 equation
 * and the same strict DER ECDSA-Sig-Value parser, widened to 48-byte r/s and a
 * 97-byte uncompressed public key. Needed for Let's Encrypt E-series and other
 * P-384 certificate chains and the ecdsa_secp384r1_sha384 TLS signature scheme.
 * Verify-only, public data, nothing constant-time. Freestanding. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Verify an ECDSA-P384-SHA384 signature. `pub` is 0x04 || X || Y (97 bytes);
 * `hash` is the 48-byte SHA-384 digest; `sig_der` is the DER ECDSA-Sig-Value.
 * Returns 0 iff the key is valid, the signature parses strictly, and the
 * verification equation holds; -1 otherwise. */
int ecdsa_p384_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t hash[48],
                      const uint8_t *sig_der, size_t sig_len);

/* Parse a strict X9.62 DER ECDSA-Sig-Value into 48-byte big-endian r and s.
 * Returns 0 on a well-formed encoding, -1 otherwise. Exposed for the X.509
 * ecdsa-with-SHA384 path. */
int ecdsa384_sig_from_der(const uint8_t *der, size_t len, uint8_t r[48], uint8_t s[48]);
