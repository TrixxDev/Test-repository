/* NIST P-384 scalar arithmetic (mod n) — see p384_scalar.h.
 *
 * add/sub are native; reduce/mul/inv route through the verified bignum library
 * (the order n has no Solinas shape, and ECDSA verify does only a handful of
 * scalar ops, so a fast reduction would buy nothing). Same structure as the
 * P-256 scalar module, widened to 12 limbs. Verify-only, not constant-time. */
#include "p384_scalar.h"
#include "bignum.h"

/* n = order of G, little-endian 32-bit limbs. */
static const uint32_t N[12] = {
    0xCCC52973u, 0xECEC196Au, 0x48B0A77Au, 0x581A0DB2u,
    0xF4372DDFu, 0xC7634D81u, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

void sc384_set_zero(sc384 *r) { for (int i = 0; i < 12; i++) r->v[i] = 0; }
void sc384_copy(sc384 *r, const sc384 *a) { for (int i = 0; i < 12; i++) r->v[i] = a->v[i]; }

int sc384_is_zero(const sc384 *a)
{
    uint32_t x = 0;
    for (int i = 0; i < 12; i++) x |= a->v[i];
    return x == 0;
}

int sc384_equal(const sc384 *a, const sc384 *b)
{
    uint32_t x = 0;
    for (int i = 0; i < 12; i++) x |= (a->v[i] ^ b->v[i]);
    return x == 0;
}

static int cmp12(const uint32_t a[12], const uint32_t b[12])
{
    for (int i = 11; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void sub_N(uint32_t t[12])
{
    int64_t br = 0;
    for (int i = 0; i < 12; i++) {
        int64_t d = (int64_t)t[i] - N[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
}

static void add_N(uint32_t t[12])
{
    uint64_t c = 0;
    for (int i = 0; i < 12; i++) {
        uint64_t s = (uint64_t)t[i] + N[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
}

static void load_be(uint32_t v[12], const uint8_t b[48])
{
    for (int i = 0; i < 12; i++) {
        const uint8_t *p = b + (44 - i * 4);
        v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    }
}

int sc384_from_bytes(sc384 *r, const uint8_t b[48])
{
    load_be(r->v, b);
    return cmp12(r->v, N) < 0 ? 0 : -1;
}

void sc384_to_bytes(uint8_t b[48], const sc384 *a)
{
    for (int i = 0; i < 12; i++) {
        uint8_t *p = b + (44 - i * 4);
        p[0] = (uint8_t)(a->v[i] >> 24); p[1] = (uint8_t)(a->v[i] >> 16);
        p[2] = (uint8_t)(a->v[i] >> 8);  p[3] = (uint8_t)(a->v[i]);
    }
}

/* ---- bignum-backed reduction / mul / inv ---- */

static void sc_to_bn(bignum *r, const sc384 *a)
{ bignum_zero(r); for (int i = 0; i < 12; i++) r->v[i] = a->v[i]; }

static void bn_to_sc(sc384 *r, const bignum *a)
{ for (int i = 0; i < 12; i++) r->v[i] = a->v[i]; }

static void load_N_bn(bignum *m)
{ bignum_zero(m); for (int i = 0; i < 12; i++) m->v[i] = N[i]; }

void sc384_reduce(sc384 *r, const uint8_t b[48])
{
    bignum A, M, R;
    bignum_from_bytes(&A, b, 48); load_N_bn(&M);
    bignum_mod(&R, &A, &M);
    bn_to_sc(r, &R);
}

void sc384_add(sc384 *r, const sc384 *a, const sc384 *b)
{
    uint32_t t[12]; uint64_t c = 0;
    for (int i = 0; i < 12; i++) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
    if (c || cmp12(t, N) >= 0) sub_N(t);
    for (int i = 0; i < 12; i++) r->v[i] = t[i];
}

void sc384_sub(sc384 *r, const sc384 *a, const sc384 *b)
{
    uint32_t t[12]; int64_t br = 0;
    for (int i = 0; i < 12; i++) {
        int64_t d = (int64_t)a->v[i] - b->v[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
    if (br) add_N(t);
    for (int i = 0; i < 12; i++) r->v[i] = t[i];
}

void sc384_mul(sc384 *r, const sc384 *a, const sc384 *b)
{
    bignum A, B, M, R;
    sc_to_bn(&A, a); sc_to_bn(&B, b); load_N_bn(&M);
    bignum_modmul(&R, &A, &B, &M);
    bn_to_sc(r, &R);
}

void sc384_inv(sc384 *r, const sc384 *a)
{
    bignum A, M, E, two, R;
    sc_to_bn(&A, a); load_N_bn(&M);
    bignum_set_u32(&two, 2); bignum_sub(&E, &M, &two);     /* E = n - 2 */
    bignum_modexp(&R, &A, &E, &M);
    bn_to_sc(r, &R);
}
