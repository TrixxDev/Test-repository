/* NIST P-384 curve points in Jacobian projective coordinates.
 *
 * Same design as the P-256 point module (a = -3, explicit infinity flag, one
 * field inversion per scalar multiply done at the end in p384_to_affine), widened
 * to the 384-bit field/scalar rings. Verify-only, nothing constant-time.
 * Freestanding. */
#pragma once
#include "p384_field.h"
#include "p384_scalar.h"

typedef struct {
    fe384 X, Y, Z;
    int   infinity;     /* 1 = point at infinity (group identity) */
} p384_point;

void p384_set_infinity(p384_point *r);
int  p384_is_infinity(const p384_point *p);

void p384_base_point(p384_point *r);                                  /* r = G (Z=1) */
void p384_from_affine(p384_point *r, const fe384 *x, const fe384 *y); /* (x,y)->Jacobian */
int  p384_to_affine(fe384 *x, fe384 *y, const p384_point *p);         /* -1 if infinity */

void p384_double(p384_point *r, const p384_point *p);                    /* r = 2P  */
void p384_add(p384_point *r, const p384_point *a, const p384_point *b);  /* r = A + B */
void p384_scalar_mul(p384_point *r, const sc384 *k, const p384_point *p);/* r = k*P */

/* 1 if the affine (x,y) satisfies y^2 = x^3 - 3x + b (mod p), else 0. */
int  p384_on_curve(const fe384 *x, const fe384 *y);

/* Decode and FULLY VALIDATE an uncompressed public key 0x04 || X || Y (97 bytes)
 * into Q. Rejects: wrong length/prefix, X>=p or Y>=p, a point not on the curve,
 * and (defense in depth) any point with n*Q != O. Returns 0 if Q is valid. */
int  p384_pubkey_decode(p384_point *Q, const uint8_t *in, size_t len);
