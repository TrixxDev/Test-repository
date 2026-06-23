/* NIST P-256 curve points in Jacobian projective coordinates.
 *
 * A point is (X:Y:Z) with affine (x,y) = (X/Z^2, Y/Z^3); the group identity (point
 * at infinity) is an EXPLICIT flag, never magic coordinates -- so add(P,O)=P,
 * double(O)=O and scalar_mul(0,P)=O are obvious rather than special-cased by
 * sentinel values. Jacobian coordinates are a near-necessity here: add/double need
 * no field inversion, so a 256-bit scalar multiply does just ONE inversion at the
 * very end (in p256_to_affine) instead of one per step (our fe_inv is the slow
 * bignum path). Verify-only, so nothing is constant-time.
 *
 * Geometry uses the field ring (p256_field); scalar multiply also reads the scalar
 * ring (p256_scalar) for the multiplier bits. Freestanding. */
#pragma once
#include "p256_field.h"
#include "p256_scalar.h"

typedef struct {
    fe  X, Y, Z;
    int infinity;     /* 1 = point at infinity (group identity) */
} p256_point;

void p256_set_infinity(p256_point *r);
int  p256_is_infinity(const p256_point *p);

void p256_base_point(p256_point *r);                            /* r = G (affine, Z=1) */
void p256_from_affine(p256_point *r, const fe *x, const fe *y); /* (x,y) -> Jacobian, Z=1 */
int  p256_to_affine(fe *x, fe *y, const p256_point *p);         /* returns -1 if infinity */

void p256_double(p256_point *r, const p256_point *p);                 /* r = 2P  */
void p256_add(p256_point *r, const p256_point *a, const p256_point *b); /* r = A + B */
void p256_scalar_mul(p256_point *r, const sc *k, const p256_point *p);  /* r = k*P */

/* 1 if the affine (x,y) satisfies y^2 = x^3 - 3x + b (mod p), else 0. */
int  p256_on_curve(const fe *x, const fe *y);

/* Decode and FULLY VALIDATE an uncompressed public key 0x04 || X || Y (65 bytes)
 * into Q. Rejects: wrong length/prefix, X>=p or Y>=p, a point not on the curve,
 * and (defense in depth) any point with n*Q != O. Returns 0 if Q is a valid
 * public key, -1 otherwise. */
int  p256_pubkey_decode(p256_point *Q, const uint8_t *in, size_t len);
