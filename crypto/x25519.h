/* X25519 (RFC 7748) — Diffie-Hellman key agreement on Curve25519. The last
 * fundamental primitive for TLS 1.3: the ECDHE shared secret it produces is the
 * input to the HKDF key schedule.
 *
 * Constant-time Montgomery ladder; field arithmetic mod 2^255-19 in 16 limbs of
 * radix 2^16, so it needs only 64-bit multiplies (no 128-bit type) and is
 * portable to plain i686. Portable + freestanding like the rest of crypto/. */
#pragma once
#include <stdint.h>

#define X25519_KEY_LEN 32

/* out = scalar * point. All values are 32-byte little-endian u-coordinates.
 * The scalar is clamped internally (RFC 7748 §5), so a raw 32-byte secret may
 * be passed directly. */
void x25519(uint8_t out[X25519_KEY_LEN],
            const uint8_t scalar[X25519_KEY_LEN],
            const uint8_t point[X25519_KEY_LEN]);

/* Public key from a secret scalar: out = scalar * basepoint(u=9). */
void x25519_base(uint8_t out[X25519_KEY_LEN],
                 const uint8_t scalar[X25519_KEY_LEN]);
