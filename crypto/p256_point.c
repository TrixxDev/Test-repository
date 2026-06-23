/* NIST P-256 point arithmetic (Jacobian, a = -3) — see p256_point.h.
 * Formulas: EFD dbl-2001-b (doubling, a=-3) and add-2007-bl (addition). */
#include "p256_point.h"

/* Base point G, little-endian field limbs. */
static const fe G_X = {{ 0xd898c296u,0xf4a13945u,0x2deb33a0u,0x77037d81u,
                         0x63a440f2u,0xf8bce6e5u,0xe12c4247u,0x6b17d1f2u }};
static const fe G_Y = {{ 0x37bf51f5u,0xcbb64068u,0x6b315eceu,0x2bce3357u,
                         0x7c0f9e16u,0x8ee7eb4au,0xfe1a7f9bu,0x4fe342e2u }};
/* curve constant b, little-endian field limbs */
static const fe CURVE_B = {{ 0x27d2604bu,0x3bce3c3eu,0xcc53b0f6u,0x651d06b0u,
                             0x769886bcu,0xb3ebbd55u,0xaa3a93e7u,0x5ac635d8u }};
/* n (group order) as a scalar, for the n*Q = O membership check */
static const sc CURVE_N = {{ 0xFC632551u,0xF3B9CAC2u,0xA7179E84u,0xBCE6FAADu,
                             0xFFFFFFFFu,0xFFFFFFFFu,0x00000000u,0xFFFFFFFFu }};

/* small helpers built on the field ring */
static void fe_mul2(fe *r, const fe *a) { fe_add(r, a, a); }
static void fe_mul3(fe *r, const fe *a) { fe t; fe_add(&t, a, a); fe_add(r, &t, a); }
static void fe_mul4(fe *r, const fe *a) { fe t; fe_add(&t, a, a); fe_add(r, &t, &t); }
static void fe_mul8(fe *r, const fe *a) { fe t; fe_mul4(&t, a); fe_add(r, &t, &t); }

void p256_set_infinity(p256_point *r)
{
    fe_set_zero(&r->X); fe_set_u32(&r->Y, 1); fe_set_zero(&r->Z);
    r->infinity = 1;
}

int p256_is_infinity(const p256_point *p) { return p->infinity; }

void p256_from_affine(p256_point *r, const fe *x, const fe *y)
{
    fe_copy(&r->X, x); fe_copy(&r->Y, y); fe_set_u32(&r->Z, 1);
    r->infinity = 0;
}

void p256_base_point(p256_point *r) { p256_from_affine(r, &G_X, &G_Y); }

int p256_to_affine(fe *x, fe *y, const p256_point *p)
{
    if (p->infinity) return -1;
    fe zinv, zinv2, zinv3;
    fe_inv(&zinv, &p->Z);
    fe_sqr(&zinv2, &zinv);
    fe_mul(&zinv3, &zinv2, &zinv);
    fe_mul(x, &p->X, &zinv2);
    fe_mul(y, &p->Y, &zinv3);
    return 0;
}

void p256_double(p256_point *r, const p256_point *p)
{
    if (p->infinity || fe_is_zero(&p->Y)) { p256_set_infinity(r); return; }

    fe delta, gamma, beta, alpha, t1, t2, x3, y3, z3, tmp;
    fe_sqr(&delta, &p->Z);                 /* delta = Z^2            */
    fe_sqr(&gamma, &p->Y);                 /* gamma = Y^2            */
    fe_mul(&beta, &p->X, &gamma);          /* beta  = X*gamma        */
    fe_sub(&t1, &p->X, &delta);            /* X - delta              */
    fe_add(&t2, &p->X, &delta);            /* X + delta              */
    fe_mul(&tmp, &t1, &t2);                /* (X-delta)(X+delta)     */
    fe_mul3(&alpha, &tmp);                 /* alpha = 3*(...)        */

    fe_sqr(&x3, &alpha);                    /* X3 = alpha^2 - 8*beta  */
    fe_mul8(&tmp, &beta);
    fe_sub(&x3, &x3, &tmp);

    fe_add(&tmp, &p->Y, &p->Z);            /* Z3 = (Y+Z)^2 - gamma - delta */
    fe_sqr(&z3, &tmp);
    fe_sub(&z3, &z3, &gamma);
    fe_sub(&z3, &z3, &delta);

    fe_mul4(&tmp, &beta);                   /* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
    fe_sub(&tmp, &tmp, &x3);
    fe_mul(&y3, &alpha, &tmp);
    fe_sqr(&tmp, &gamma);
    fe_mul8(&tmp, &tmp);
    fe_sub(&y3, &y3, &tmp);

    fe_copy(&r->X, &x3); fe_copy(&r->Y, &y3); fe_copy(&r->Z, &z3);
    r->infinity = fe_is_zero(&z3);
}

void p256_add(p256_point *r, const p256_point *a, const p256_point *b)
{
    if (a->infinity) { *r = *b; return; }
    if (b->infinity) { *r = *a; return; }

    fe Z1Z1, Z2Z2, U1, U2, S1, S2, H, R, t;
    fe_sqr(&Z1Z1, &a->Z);
    fe_sqr(&Z2Z2, &b->Z);
    fe_mul(&U1, &a->X, &Z2Z2);             /* U1 = X1*Z2^2 */
    fe_mul(&U2, &b->X, &Z1Z1);             /* U2 = X2*Z1^2 */
    fe_mul(&t, &b->Z, &Z2Z2); fe_mul(&S1, &a->Y, &t);   /* S1 = Y1*Z2^3 */
    fe_mul(&t, &a->Z, &Z1Z1); fe_mul(&S2, &b->Y, &t);   /* S2 = Y2*Z1^3 */
    fe_sub(&H, &U2, &U1);
    fe_sub(&R, &S2, &S1); fe_mul2(&R, &R);              /* R = 2*(S2-S1) */

    if (fe_is_zero(&H)) {                   /* same x-coordinate */
        if (fe_is_zero(&R)) { p256_double(r, a); return; }  /* P == Q  */
        p256_set_infinity(r); return;                       /* P == -Q */
    }

    fe I, J, V, x3, y3, z3, tmp;
    fe_mul2(&tmp, &H); fe_sqr(&I, &tmp);   /* I = (2H)^2 */
    fe_mul(&J, &H, &I);                     /* J = H*I    */
    fe_mul(&V, &U1, &I);                    /* V = U1*I   */

    fe_sqr(&x3, &R);                        /* X3 = R^2 - J - 2V */
    fe_sub(&x3, &x3, &J);
    fe_mul2(&tmp, &V); fe_sub(&x3, &x3, &tmp);

    fe_sub(&tmp, &V, &x3);                  /* Y3 = R*(V - X3) - 2*S1*J */
    fe_mul(&y3, &R, &tmp);
    fe_mul(&tmp, &S1, &J); fe_mul2(&tmp, &tmp);
    fe_sub(&y3, &y3, &tmp);

    fe_add(&tmp, &a->Z, &b->Z);            /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H */
    fe_sqr(&z3, &tmp);
    fe_sub(&z3, &z3, &Z1Z1);
    fe_sub(&z3, &z3, &Z2Z2);
    fe_mul(&z3, &z3, &H);

    fe_copy(&r->X, &x3); fe_copy(&r->Y, &y3); fe_copy(&r->Z, &z3);
    r->infinity = fe_is_zero(&z3);
}

void p256_scalar_mul(p256_point *r, const sc *k, const p256_point *p)
{
    p256_point R;
    p256_set_infinity(&R);
    for (int i = 255; i >= 0; i--) {
        p256_double(&R, &R);
        if ((k->v[i >> 5] >> (i & 31)) & 1) p256_add(&R, &R, p);
    }
    *r = R;
}

int p256_on_curve(const fe *x, const fe *y)
{
    fe rhs, t, y2;
    fe_sqr(&rhs, x); fe_mul(&rhs, &rhs, x);     /* x^3            */
    fe_add(&t, x, x); fe_add(&t, &t, x);        /* 3x             */
    fe_sub(&rhs, &rhs, &t);                      /* x^3 - 3x       */
    fe_add(&rhs, &rhs, &CURVE_B);                /* x^3 - 3x + b   */
    fe_sqr(&y2, y);                              /* y^2            */
    return fe_equal(&y2, &rhs);
}

int p256_pubkey_decode(p256_point *Q, const uint8_t *in, size_t len)
{
    fe x, y;
    if (len != 65 || in[0] != 0x04) return -1;         /* uncompressed only */
    if (fe_from_bytes(&x, in + 1)  != 0) return -1;    /* X >= p  -> reject */
    if (fe_from_bytes(&y, in + 33) != 0) return -1;    /* Y >= p  -> reject */
    if (!p256_on_curve(&x, &y)) return -1;             /* must satisfy curve eqn */

    p256_from_affine(Q, &x, &y);                       /* finite point (never O) */

    /* Defense in depth: n*Q must be O. On P-256 (cofactor 1) being on-curve and
     * != O already implies this, but the check also cross-validates scalar_mul
     * and catches a point that slipped the curve equation. */
    p256_point nQ;
    p256_scalar_mul(&nQ, &CURVE_N, Q);
    if (!p256_is_infinity(&nQ)) return -1;
    return 0;
}
