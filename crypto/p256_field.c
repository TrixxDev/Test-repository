/* NIST P-256 field arithmetic (mod p) — see p256_field.h. */
#include "p256_field.h"
#include "bignum.h"

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1, little-endian 32-bit limbs. */
static const uint32_t P[8] = {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
};

void fe_set_zero(fe *r) { for (int i = 0; i < 8; i++) r->v[i] = 0; }
void fe_copy(fe *r, const fe *a) { for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }
void fe_set_u32(fe *r, uint32_t x) { fe_set_zero(r); r->v[0] = x; }

int fe_is_zero(const fe *a)
{
    uint32_t x = 0;
    for (int i = 0; i < 8; i++) x |= a->v[i];
    return x == 0;
}

int fe_equal(const fe *a, const fe *b)
{
    uint32_t x = 0;
    for (int i = 0; i < 8; i++) x |= (a->v[i] ^ b->v[i]);
    return x == 0;
}

/* Compare an 8-limb value to a constant 8-limb value: -1 / 0 / 1. */
static int cmp8(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/* t -= P (mod 2^256), borrow ignored by the caller (it is always cancelled). */
static void sub_P(uint32_t t[8])
{
    int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)t[i] - P[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
}

/* t += P (mod 2^256), carry ignored by the caller. */
static void add_P(uint32_t t[8])
{
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)t[i] + P[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
}

int fe_from_bytes(fe *r, const uint8_t b[32])
{
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + (28 - i * 4);          /* big-endian: limb 0 is last */
        r->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                  ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    }
    return cmp8(r->v, P) < 0 ? 0 : -1;                 /* reject >= p */
}

void fe_to_bytes(uint8_t b[32], const fe *a)
{
    for (int i = 0; i < 8; i++) {
        uint8_t *p = b + (28 - i * 4);
        p[0] = (uint8_t)(a->v[i] >> 24); p[1] = (uint8_t)(a->v[i] >> 16);
        p[2] = (uint8_t)(a->v[i] >> 8);  p[3] = (uint8_t)(a->v[i]);
    }
}

void fe_add(fe *r, const fe *a, const fe *b)
{
    uint32_t t[8]; uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
    /* a,b < p so a+b < 2p: one conditional subtract reduces. When c==1 the value
     * is 2^256+t with t<p, and (sub_P)'s borrow cancels the 2^256. */
    if (c || cmp8(t, P) >= 0) sub_P(t);
    for (int i = 0; i < 8; i++) r->v[i] = t[i];
}

void fe_sub(fe *r, const fe *a, const fe *b)
{
    uint32_t t[8]; int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)a->v[i] - b->v[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
    if (br) add_P(t);                                  /* a<b: add p once */
    for (int i = 0; i < 8; i++) r->v[i] = t[i];
}

/* ---- mul/sqr/inv via the verified bignum (correct first pass) ---- */

static void fe_to_bn(bignum *r, const fe *a)
{ bignum_zero(r); for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }

static void bn_to_fe(fe *r, const bignum *a)
{ for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }

static void load_P_bn(bignum *m)
{ bignum_zero(m); for (int i = 0; i < 8; i++) m->v[i] = P[i]; }

void fe_mul(fe *r, const fe *a, const fe *b)
{
    bignum A, B, M, R;
    fe_to_bn(&A, a); fe_to_bn(&B, b); load_P_bn(&M);
    bignum_modmul(&R, &A, &B, &M);
    bn_to_fe(r, &R);
}

void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

void fe_inv(fe *r, const fe *a)
{
    /* Fermat: a^(p-2) mod p. Reuses the verified modexp; fe_inv(0) yields 0. */
    bignum A, M, E, two, R;
    fe_to_bn(&A, a); load_P_bn(&M);
    bignum_set_u32(&two, 2); bignum_sub(&E, &M, &two);     /* E = p - 2 */
    bignum_modexp(&R, &A, &E, &M);
    bn_to_fe(r, &R);
}
