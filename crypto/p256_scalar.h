/* NIST P-256 scalar arithmetic — the group-order ring GF(n), where
 *   n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 * is the order of the base point G.
 *
 * Deliberately a SEPARATE module from the field (mod p): they are different rings
 * and keeping them apart localizes bugs. ECDSA verification lives here —
 *   w = s^-1 mod n,  u1 = e*w mod n,  u2 = r*w mod n,  and  x_R mod n
 * — so this exposes mul/inv/reduce plus the range checks for r,s. Verify-only
 * (public data), nothing constant-time. A scalar is 8 little-endian 32-bit limbs.
 * Freestanding: <stdint.h>/<stddef.h> only. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t v[8]; } sc;     /* 256-bit, little-endian limbs */

void sc_set_zero(sc *r);
void sc_copy(sc *r, const sc *a);
int  sc_is_zero(const sc *a);
int  sc_equal(const sc *a, const sc *b);

/* Load a 32-byte big-endian value. Returns 0 if it is < n (already reduced), -1
 * otherwise. With sc_is_zero this gives the ECDSA range test 1 <= x <= n-1. */
int  sc_from_bytes(sc *r, const uint8_t b[32]);
void sc_to_bytes(uint8_t b[32], const sc *a);

/* Reduce an arbitrary 32-byte big-endian value mod n (for the message hash e and
 * for x_R mod n in the final comparison). */
void sc_reduce(sc *r, const uint8_t b[32]);

void sc_add(sc *r, const sc *a, const sc *b);   /* r = (a + b) mod n */
void sc_sub(sc *r, const sc *a, const sc *b);   /* r = (a - b) mod n */
void sc_mul(sc *r, const sc *a, const sc *b);   /* r = (a * b) mod n */
void sc_inv(sc *r, const sc *a);                /* r = a^(n-2) mod n; sc_inv(0) = 0 */
