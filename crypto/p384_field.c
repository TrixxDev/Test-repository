/* NIST P-384 field arithmetic (mod p) — see p384_field.h.
 *
 * add/sub are native. mul/sqr use a 12x12 schoolbook multiply followed by a fast
 * reduction that exploits the shape of p: with R0 = 2^384 - p = 2^128 + 2^96 -
 * 2^32 + 1, any value = low + high*2^384 reduces as low + high*R0 (mod p), and
 * because 128/96/32 are whole multiples of 32 the high*R0 folds are WORD-aligned
 * shifts (by 4/3/1/0 limbs) -- no bit shifting. R0 > 0 so value = low + high*R0
 * stays non-negative; the fold loop converges to a < 2^384 result needing one
 * final conditional subtract. inv is Fermat (a^(p-2)) over these fast mul/sqr.
 * This is the same shape as the P-256 module. Verify-only, not constant-time. */
#include "p384_field.h"

/* p, little-endian 32-bit limbs:
 *   ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
 *   ffffffff fffffffe ffffffff 00000000 00000000 ffffffff   (big-endian) */
static const uint32_t P[12] = {
    0xFFFFFFFFu, 0x00000000u, 0x00000000u, 0xFFFFFFFFu,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

void fe384_set_zero(fe384 *r) { for (int i = 0; i < 12; i++) r->v[i] = 0; }
void fe384_copy(fe384 *r, const fe384 *a) { for (int i = 0; i < 12; i++) r->v[i] = a->v[i]; }
void fe384_set_u32(fe384 *r, uint32_t x) { fe384_set_zero(r); r->v[0] = x; }

int fe384_is_zero(const fe384 *a)
{
    uint32_t x = 0;
    for (int i = 0; i < 12; i++) x |= a->v[i];
    return x == 0;
}

int fe384_equal(const fe384 *a, const fe384 *b)
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

static void sub_P(uint32_t t[12])
{
    int64_t br = 0;
    for (int i = 0; i < 12; i++) {
        int64_t d = (int64_t)t[i] - P[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
}

static void add_P(uint32_t t[12])
{
    uint64_t c = 0;
    for (int i = 0; i < 12; i++) {
        uint64_t s = (uint64_t)t[i] + P[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
}

int fe384_from_bytes(fe384 *r, const uint8_t b[48])
{
    for (int i = 0; i < 12; i++) {
        const uint8_t *p = b + (44 - i * 4);
        r->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                  ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    }
    return cmp12(r->v, P) < 0 ? 0 : -1;
}

void fe384_to_bytes(uint8_t b[48], const fe384 *a)
{
    for (int i = 0; i < 12; i++) {
        uint8_t *p = b + (44 - i * 4);
        p[0] = (uint8_t)(a->v[i] >> 24); p[1] = (uint8_t)(a->v[i] >> 16);
        p[2] = (uint8_t)(a->v[i] >> 8);  p[3] = (uint8_t)(a->v[i]);
    }
}

void fe384_add(fe384 *r, const fe384 *a, const fe384 *b)
{
    uint32_t t[12]; uint64_t c = 0;
    for (int i = 0; i < 12; i++) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + c;
        t[i] = (uint32_t)s; c = s >> 32;
    }
    if (c || cmp12(t, P) >= 0) sub_P(t);
    for (int i = 0; i < 12; i++) r->v[i] = t[i];
}

void fe384_sub(fe384 *r, const fe384 *a, const fe384 *b)
{
    uint32_t t[12]; int64_t br = 0;
    for (int i = 0; i < 12; i++) {
        int64_t d = (int64_t)a->v[i] - b->v[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
    if (br) add_P(t);
    for (int i = 0; i < 12; i++) r->v[i] = t[i];
}

/* 12x12 -> 24-limb schoolbook multiply. */
static void mul12(uint32_t r[24], const uint32_t a[12], const uint32_t b[12])
{
    for (int i = 0; i < 24; i++) r[i] = 0;
    for (int i = 0; i < 12; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 12; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        r[i + 12] = (uint32_t)carry;
    }
}

/* Reduce a 24-limb (768-bit) value mod p into r[12], via word-aligned folds:
 *   value = low + high*2^384 ≡ low + high*R0 (mod p),  R0 = 2^128+2^96-2^32+1.
 * high*R0 = (high<<128) + (high<<96) - (high<<32) + high, all shifts by whole
 * limbs (4/3/1/0). Repeat until the high half is zero; one final subtract of p. */
static void fe384_reduce(uint32_t r[12], const uint32_t in[24])
{
    int64_t v[24];
    for (int i = 0; i < 24; i++) v[i] = in[i];

    for (int iter = 0; iter < 16; iter++) {
        int64_t carry = 0;                          /* normalize to base 2^32 */
        for (int i = 0; i < 24; i++) {
            int64_t x = v[i] + carry;
            v[i] = (uint32_t)x;                      /* low 32 bits (mod 2^32) */
            carry = x >> 32;                         /* arithmetic shift = floor */
        }
        int hi = 0;
        for (int i = 12; i < 24; i++) if (v[i]) { hi = 1; break; }
        if (!hi) break;

        uint32_t h[12];
        for (int i = 0; i < 12; i++) { h[i] = (uint32_t)v[12 + i]; v[12 + i] = 0; }
        for (int i = 0; i < 12; i++) {               /* v += high*R0 */
            int64_t hi64 = (int64_t)h[i];
            v[0 + i] += hi64;                        /* + high       */
            v[1 + i] -= hi64;                        /* - high<<32   */
            v[3 + i] += hi64;                        /* + high<<96   */
            v[4 + i] += hi64;                        /* + high<<128  */
        }
    }

    for (int i = 0; i < 12; i++) r[i] = (uint32_t)v[i];  /* now < 2^384, >= 0 */
    if (cmp12(r, P) >= 0) sub_P(r);                      /* < 2^384 < 2p -> one subtract */
}

void fe384_mul(fe384 *r, const fe384 *a, const fe384 *b)
{
    uint32_t prod[24];
    mul12(prod, a->v, b->v);
    fe384_reduce(r->v, prod);
}

void fe384_sqr(fe384 *r, const fe384 *a) { fe384_mul(r, a, a); }

void fe384_inv(fe384 *r, const fe384 *a)
{
    /* Fermat: a^(p-2) mod p, exponent p-2 in little-endian limbs. inv(0)=0. */
    static const uint32_t E[12] = {
        0xFFFFFFFDu, 0x00000000u, 0x00000000u, 0xFFFFFFFFu,
        0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
    };
    fe384 x; fe384_set_u32(&x, 1);
    for (int i = 383; i >= 0; i--) {
        fe384_sqr(&x, &x);
        if ((E[i >> 5] >> (i & 31)) & 1) fe384_mul(&x, &x, a);
    }
    fe384_copy(r, &x);
}
