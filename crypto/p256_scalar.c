/* NIST P-256 scalar arithmetic (mod n) — see p256_scalar.h. */
#include "p256_scalar.h"
#include "bignum.h"

/* n = order of G, little-endian 32-bit limbs. */
static const uint32_t N[8] = {
    0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu
};

void sc_set_zero(sc *r) { for (int i = 0; i < 8; i++) r->v[i] = 0; }
void sc_copy(sc *r, const sc *a) { for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }

int sc_is_zero(const sc *a)
{
    uint32_t x = 0;
    for (int i = 0; i < 8; i++) x |= a->v[i];
    return x == 0;
}

int sc_equal(const sc *a, const sc *b)
{
    uint32_t x = 0;
    for (int i = 0; i < 8; i++) x |= (a->v[i] ^ b->v[i]);
    return x == 0;
}

static int cmp8(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void sub_N(uint32_t t[8])
{
    int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)t[i] - N[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
}

static void add_N(uint32_t t[8])
{
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)t[i] + N[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
}

static void load_be(uint32_t v[8], const uint8_t b[32])
{
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + (28 - i * 4);
        v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    }
}

int sc_from_bytes(sc *r, const uint8_t b[32])
{
    load_be(r->v, b);
    return cmp8(r->v, N) < 0 ? 0 : -1;
}

void sc_to_bytes(uint8_t b[32], const sc *a)
{
    for (int i = 0; i < 8; i++) {
        uint8_t *p = b + (28 - i * 4);
        p[0] = (uint8_t)(a->v[i] >> 24); p[1] = (uint8_t)(a->v[i] >> 16);
        p[2] = (uint8_t)(a->v[i] >> 8);  p[3] = (uint8_t)(a->v[i]);
    }
}

/* ---- bignum-backed reduction / mul / inv (correct first pass) ---- */

static void sc_to_bn(bignum *r, const sc *a)
{ bignum_zero(r); for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }

static void bn_to_sc(sc *r, const bignum *a)
{ for (int i = 0; i < 8; i++) r->v[i] = a->v[i]; }

static void load_N_bn(bignum *m)
{ bignum_zero(m); for (int i = 0; i < 8; i++) m->v[i] = N[i]; }

void sc_reduce(sc *r, const uint8_t b[32])
{
    bignum A, M, R;
    bignum_from_bytes(&A, b, 32); load_N_bn(&M);
    bignum_mod(&R, &A, &M);
    bn_to_sc(r, &R);
}

void sc_add(sc *r, const sc *a, const sc *b)
{
    uint32_t t[8]; uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
    if (c || cmp8(t, N) >= 0) sub_N(t);
    for (int i = 0; i < 8; i++) r->v[i] = t[i];
}

void sc_sub(sc *r, const sc *a, const sc *b)
{
    uint32_t t[8]; int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)a->v[i] - b->v[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
    if (br) add_N(t);
    for (int i = 0; i < 8; i++) r->v[i] = t[i];
}

void sc_mul(sc *r, const sc *a, const sc *b)
{
    bignum A, B, M, R;
    sc_to_bn(&A, a); sc_to_bn(&B, b); load_N_bn(&M);
    bignum_modmul(&R, &A, &B, &M);
    bn_to_sc(r, &R);
}

void sc_inv(sc *r, const sc *a)
{
    bignum A, M, E, two, R;
    sc_to_bn(&A, a); load_N_bn(&M);
    bignum_set_u32(&two, 2); bignum_sub(&E, &M, &two);     /* E = n - 2 */
    bignum_modexp(&R, &A, &E, &M);
    bn_to_sc(r, &R);
}
