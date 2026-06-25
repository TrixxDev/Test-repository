/* NIST P-384 (secp384r1) field arithmetic — GF(p), where
 *   p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
 *
 * The *field* ring only (mod p): the coordinate arithmetic for the curve. The
 * scalar ring (mod n, the group order) is the separate p384_scalar.* module —
 * different rings, kept apart to localize bugs. Verify-only (public data), so
 * nothing here is constant-time.
 *
 * A field element is 12 little-endian 32-bit limbs, kept fully reduced in [0, p).
 * Mirrors the P-256 fe API exactly (only the width and the reduction constant
 * differ), so the curve/ECDSA layer treats the two curves uniformly.
 * Freestanding: <stdint.h>/<stddef.h> only. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t v[12]; } fe384;     /* 384-bit, little-endian limbs, < p */

void fe384_set_zero(fe384 *r);
void fe384_set_u32(fe384 *r, uint32_t x);
void fe384_copy(fe384 *r, const fe384 *a);
int  fe384_is_zero(const fe384 *a);
int  fe384_equal(const fe384 *a, const fe384 *b);   /* 1 if equal, else 0 */

/* 48-byte big-endian I/O. fe384_from_bytes returns 0 if the value is a valid
 * field element (< p) and -1 otherwise (over-large input is rejected, not
 * reduced) — exactly what validating an external coordinate needs. */
int  fe384_from_bytes(fe384 *r, const uint8_t b[48]);
void fe384_to_bytes(uint8_t b[48], const fe384 *a);

void fe384_add(fe384 *r, const fe384 *a, const fe384 *b);   /* r = (a + b) mod p */
void fe384_sub(fe384 *r, const fe384 *a, const fe384 *b);   /* r = (a - b) mod p */
void fe384_mul(fe384 *r, const fe384 *a, const fe384 *b);   /* r = (a * b) mod p */
void fe384_sqr(fe384 *r, const fe384 *a);                   /* r = (a * a) mod p */
void fe384_inv(fe384 *r, const fe384 *a);                   /* r = a^(p-2); inv(0)=0 */
