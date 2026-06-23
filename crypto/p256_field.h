/* NIST P-256 (secp256r1) field arithmetic — GF(p), where
 *   p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
 *
 * This is the *field* ring only (mod p): the coordinate arithmetic for the curve.
 * The scalar ring (mod n, the group order) is a deliberately separate module
 * (p256_scalar.*) — they are different rings and keeping them apart localizes
 * bugs. Verify-only use (public data), so nothing here is constant-time.
 *
 * A field element is 8 little-endian 32-bit limbs, always kept fully reduced in
 * [0, p). add/sub are native; mul/sqr/inv route through the verified bignum
 * (schoolbook multiply + reduction) for a correct first pass — the fe API is the
 * stable seam, so the internals can later become a dedicated fast reduction
 * without any caller change. Freestanding: <stdint.h>/<stddef.h> only. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t v[8]; } fe;     /* 256-bit, little-endian limbs, < p */

void fe_set_zero(fe *r);
void fe_set_u32(fe *r, uint32_t x);
void fe_copy(fe *r, const fe *a);
int  fe_is_zero(const fe *a);
int  fe_equal(const fe *a, const fe *b);  /* 1 if equal, else 0 */

/* 32-byte big-endian I/O. fe_from_bytes returns 0 if the value is a valid field
 * element (< p) and -1 otherwise (over-large input is rejected, not reduced) —
 * exactly what validating an external coordinate needs. */
int  fe_from_bytes(fe *r, const uint8_t b[32]);
void fe_to_bytes(uint8_t b[32], const fe *a);

void fe_add(fe *r, const fe *a, const fe *b);   /* r = (a + b) mod p */
void fe_sub(fe *r, const fe *a, const fe *b);   /* r = (a - b) mod p */
void fe_mul(fe *r, const fe *a, const fe *b);   /* r = (a * b) mod p */
void fe_sqr(fe *r, const fe *a);                /* r = (a * a) mod p */
void fe_inv(fe *r, const fe *a);                /* r = a^(p-2) mod p; fe_inv(0) = 0 */
