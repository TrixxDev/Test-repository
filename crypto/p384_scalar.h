/* NIST P-384 scalar arithmetic — the group-order ring GF(n), where
 *   n = ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
 *       c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973
 * is the order of the base point G.
 *
 * A SEPARATE module from the field (mod p): different rings, kept apart to
 * localize bugs. ECDSA verification lives here —
 *   w = s^-1 mod n,  u1 = e*w mod n,  u2 = r*w mod n,  and  x_R mod n
 * — so this exposes mul/inv/reduce plus the range checks for r,s. Verify-only
 * (public data), nothing constant-time. A scalar is 12 little-endian 32-bit
 * limbs. Freestanding: <stdint.h>/<stddef.h> only. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t v[12]; } sc384;     /* 384-bit, little-endian limbs */

void sc384_set_zero(sc384 *r);
void sc384_copy(sc384 *r, const sc384 *a);
int  sc384_is_zero(const sc384 *a);
int  sc384_equal(const sc384 *a, const sc384 *b);

/* Load a 48-byte big-endian value. Returns 0 if it is < n (already reduced), -1
 * otherwise. With sc384_is_zero this gives the ECDSA range test 1 <= x <= n-1. */
int  sc384_from_bytes(sc384 *r, const uint8_t b[48]);
void sc384_to_bytes(uint8_t b[48], const sc384 *a);

/* Reduce an arbitrary 48-byte big-endian value mod n (for the message hash e and
 * for x_R mod n in the final comparison). */
void sc384_reduce(sc384 *r, const uint8_t b[48]);

void sc384_add(sc384 *r, const sc384 *a, const sc384 *b);   /* r = (a + b) mod n */
void sc384_sub(sc384 *r, const sc384 *a, const sc384 *b);   /* r = (a - b) mod n */
void sc384_mul(sc384 *r, const sc384 *a, const sc384 *b);   /* r = (a * b) mod n */
void sc384_inv(sc384 *r, const sc384 *a);                   /* r = a^(n-2); inv(0)=0 */
