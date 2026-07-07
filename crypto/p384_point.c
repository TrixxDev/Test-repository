/* NIST P-384 point arithmetic (Jacobian, a = -3) — see p384_point.h.
 * Formulas: EFD dbl-2001-b (doubling, a=-3) and add-2007-bl (addition) — the same
 * as the P-256 module; only the field/scalar width and the curve constants differ.
 * Constants verified on-curve (y^2 = x^3 - 3x + b mod p) before use. */
#include "p384_point.h"

/* Base point G and curve constant b, little-endian field limbs (secp384r1). */
static const fe384 G_X = {{ 0x72760ab7u, 0x3a545e38u, 0xbf55296cu, 0x5502f25du,
                            0x82542a38u, 0x59f741e0u, 0x8ba79b98u, 0x6e1d3b62u,
                            0xf320ad74u, 0x8eb1c71eu, 0xbe8b0537u, 0xaa87ca22u }};
static const fe384 G_Y = {{ 0x90ea0e5fu, 0x7a431d7cu, 0x1d7e819du, 0x0a60b1ceu,
                            0xb5f0b8c0u, 0xe9da3113u, 0x289a147cu, 0xf8f41dbdu,
                            0x9292dc29u, 0x5d9e98bfu, 0x96262c6fu, 0x3617de4au }};
static const fe384 CURVE_B = {{ 0xd3ec2aefu, 0x2a85c8edu, 0x8a2ed19du, 0xc656398du,
                                0x5013875au, 0x0314088fu, 0xfe814112u, 0x181d9c6eu,
                                0xe3f82d19u, 0x988e056bu, 0xe23ee7e4u, 0xb3312fa7u }};
/* n (group order) as a scalar, for the n*Q = O membership check */
static const sc384 CURVE_N = {{ 0xCCC52973u, 0xECEC196Au, 0x48B0A77Au, 0x581A0DB2u,
                                0xF4372DDFu, 0xC7634D81u, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu }};

static void fe_mul2(fe384 *r, const fe384 *a) { fe384_add(r, a, a); }
static void fe_mul3(fe384 *r, const fe384 *a) { fe384 t; fe384_add(&t, a, a); fe384_add(r, &t, a); }
static void fe_mul4(fe384 *r, const fe384 *a) { fe384 t; fe384_add(&t, a, a); fe384_add(r, &t, &t); }
static void fe_mul8(fe384 *r, const fe384 *a) { fe384 t; fe_mul4(&t, a); fe384_add(r, &t, &t); }

void p384_set_infinity(p384_point *r)
{
    fe384_set_zero(&r->X); fe384_set_u32(&r->Y, 1); fe384_set_zero(&r->Z);
    r->infinity = 1;
}

int p384_is_infinity(const p384_point *p) { return p->infinity; }

void p384_from_affine(p384_point *r, const fe384 *x, const fe384 *y)
{
    fe384_copy(&r->X, x); fe384_copy(&r->Y, y); fe384_set_u32(&r->Z, 1);
    r->infinity = 0;
}

void p384_base_point(p384_point *r) { p384_from_affine(r, &G_X, &G_Y); }

int p384_to_affine(fe384 *x, fe384 *y, const p384_point *p)
{
    if (p->infinity) return -1;
    fe384 zinv, zinv2, zinv3;
    fe384_inv(&zinv, &p->Z);
    fe384_sqr(&zinv2, &zinv);
    fe384_mul(&zinv3, &zinv2, &zinv);
    fe384_mul(x, &p->X, &zinv2);
    fe384_mul(y, &p->Y, &zinv3);
    return 0;
}

void p384_double(p384_point *r, const p384_point *p)
{
    if (p->infinity || fe384_is_zero(&p->Y)) { p384_set_infinity(r); return; }

    fe384 delta, gamma, beta, alpha, t1, t2, x3, y3, z3, tmp;
    fe384_sqr(&delta, &p->Z);
    fe384_sqr(&gamma, &p->Y);
    fe384_mul(&beta, &p->X, &gamma);
    fe384_sub(&t1, &p->X, &delta);
    fe384_add(&t2, &p->X, &delta);
    fe384_mul(&tmp, &t1, &t2);
    fe_mul3(&alpha, &tmp);

    fe384_sqr(&x3, &alpha);                       /* X3 = alpha^2 - 8*beta */
    fe_mul8(&tmp, &beta);
    fe384_sub(&x3, &x3, &tmp);

    fe384_add(&tmp, &p->Y, &p->Z);                /* Z3 = (Y+Z)^2 - gamma - delta */
    fe384_sqr(&z3, &tmp);
    fe384_sub(&z3, &z3, &gamma);
    fe384_sub(&z3, &z3, &delta);

    fe_mul4(&tmp, &beta);                          /* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
    fe384_sub(&tmp, &tmp, &x3);
    fe384_mul(&y3, &alpha, &tmp);
    fe384_sqr(&tmp, &gamma);
    fe_mul8(&tmp, &tmp);
    fe384_sub(&y3, &y3, &tmp);

    fe384_copy(&r->X, &x3); fe384_copy(&r->Y, &y3); fe384_copy(&r->Z, &z3);
    r->infinity = fe384_is_zero(&z3);
}

void p384_add(p384_point *r, const p384_point *a, const p384_point *b)
{
    if (a->infinity) { *r = *b; return; }
    if (b->infinity) { *r = *a; return; }

    fe384 Z1Z1, Z2Z2, U1, U2, S1, S2, H, R, t;
    fe384_sqr(&Z1Z1, &a->Z);
    fe384_sqr(&Z2Z2, &b->Z);
    fe384_mul(&U1, &a->X, &Z2Z2);
    fe384_mul(&U2, &b->X, &Z1Z1);
    fe384_mul(&t, &b->Z, &Z2Z2); fe384_mul(&S1, &a->Y, &t);
    fe384_mul(&t, &a->Z, &Z1Z1); fe384_mul(&S2, &b->Y, &t);
    fe384_sub(&H, &U2, &U1);
    fe384_sub(&R, &S2, &S1); fe_mul2(&R, &R);

    if (fe384_is_zero(&H)) {
        if (fe384_is_zero(&R)) { p384_double(r, a); return; }   /* P == Q  */
        p384_set_infinity(r); return;                           /* P == -Q */
    }

    fe384 I, J, V, x3, y3, z3, tmp;
    fe_mul2(&tmp, &H); fe384_sqr(&I, &tmp);
    fe384_mul(&J, &H, &I);
    fe384_mul(&V, &U1, &I);

    fe384_sqr(&x3, &R);
    fe384_sub(&x3, &x3, &J);
    fe_mul2(&tmp, &V); fe384_sub(&x3, &x3, &tmp);

    fe384_sub(&tmp, &V, &x3);
    fe384_mul(&y3, &R, &tmp);
    fe384_mul(&tmp, &S1, &J); fe_mul2(&tmp, &tmp);
    fe384_sub(&y3, &y3, &tmp);

    fe384_add(&tmp, &a->Z, &b->Z);
    fe384_sqr(&z3, &tmp);
    fe384_sub(&z3, &z3, &Z1Z1);
    fe384_sub(&z3, &z3, &Z2Z2);
    fe384_mul(&z3, &z3, &H);

    fe384_copy(&r->X, &x3); fe384_copy(&r->Y, &y3); fe384_copy(&r->Z, &z3);
    r->infinity = fe384_is_zero(&z3);
}

void p384_scalar_mul(p384_point *r, const sc384 *k, const p384_point *p)
{
    p384_point R;
    p384_set_infinity(&R);
    for (int i = 383; i >= 0; i--) {
        p384_double(&R, &R);
        if ((k->v[i >> 5] >> (i & 31)) & 1) p384_add(&R, &R, p);
    }
    *r = R;
}

int p384_on_curve(const fe384 *x, const fe384 *y)
{
    fe384 rhs, t, y2;
    fe384_sqr(&rhs, x); fe384_mul(&rhs, &rhs, x);    /* x^3          */
    fe384_add(&t, x, x); fe384_add(&t, &t, x);       /* 3x           */
    fe384_sub(&rhs, &rhs, &t);                        /* x^3 - 3x     */
    fe384_add(&rhs, &rhs, &CURVE_B);                  /* x^3 - 3x + b */
    fe384_sqr(&y2, y);                                /* y^2          */
    return fe384_equal(&y2, &rhs);
}

int p384_pubkey_decode(p384_point *Q, const uint8_t *in, size_t len)
{
    fe384 x, y;
    if (len != 97 || in[0] != 0x04) return -1;          /* uncompressed only */
    if (fe384_from_bytes(&x, in + 1)  != 0) return -1;  /* X >= p -> reject */
    if (fe384_from_bytes(&y, in + 49) != 0) return -1;  /* Y >= p -> reject */
    if (!p384_on_curve(&x, &y)) return -1;

    p384_from_affine(Q, &x, &y);

    p384_point nQ;
    p384_scalar_mul(&nQ, &CURVE_N, Q);                  /* n*Q must be O */
    if (!p384_is_infinity(&nQ)) return -1;
    return 0;
}
