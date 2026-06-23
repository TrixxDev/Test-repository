/* NIST P-256 field arithmetic (mod p) — see p256_field.h.
 *
 * add/sub are native. mul/sqr use an 8x8 schoolbook multiply followed by a fast
 * reduction that exploits the shape of p: with R0 = 2^256 - p = 2^224 - 2^192 -
 * 2^96 + 1, any value = low + high*2^256 reduces as low + high*R0 (mod p), and
 * because 224/192/96 are whole multiples of 32 the high*R0 folds are WORD-aligned
 * shifts (by 7/6/3 limbs) -- no bit shifting. value = low + high*R0 stays
 * non-negative, so the fold loop converges to a < 2^256 result needing one final
 * conditional subtract. inv is Fermat (a^(p-2)) over these fast mul/sqr. This is
 * the same fe API the earlier bignum-backed version exposed; only the internals
 * got fast. Verify-only, not constant-time. */
#include "p256_field.h"

/* p, little-endian 32-bit limbs. */
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

static int cmp8(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void sub_P(uint32_t t[8])
{
    int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)t[i] - P[i] - br;
        if (d < 0) { d += 0x100000000LL; br = 1; } else br = 0;
        t[i] = (uint32_t)d;
    }
}

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
        const uint8_t *p = b + (28 - i * 4);
        r->v[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                  ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    }
    return cmp8(r->v, P) < 0 ? 0 : -1;
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
    if (br) add_P(t);
    for (int i = 0; i < 8; i++) r->v[i] = t[i];
}

/* 8x8 -> 16-limb schoolbook multiply. */
static void mul8(uint32_t r[16], const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 0; i < 16; i++) r[i] = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        r[i + 8] = (uint32_t)carry;
    }
}

/* Reduce a 16-limb (512-bit) value mod p into r[8], via word-aligned folds:
 *   value = low + high*2^256 ≡ low + high*R0 (mod p),  R0 = 2^224-2^192-2^96+1.
 * high*R0 = (high<<224) - (high<<192) - (high<<96) + high, all shifts by whole
 * limbs (7/6/3/0). Repeat until the high half is zero; one final subtract of p. */
static void fe_reduce(uint32_t r[8], const uint32_t in[16])
{
    int64_t v[16];
    for (int i = 0; i < 16; i++) v[i] = in[i];

    for (int iter = 0; iter < 16; iter++) {
        int64_t carry = 0;                          /* normalize to base 2^32 */
        for (int i = 0; i < 16; i++) {
            int64_t x = v[i] + carry;
            v[i] = (uint32_t)x;                      /* low 32 bits (mod 2^32) */
            carry = x >> 32;                         /* arithmetic shift = floor */
        }
        int hi = 0;
        for (int i = 8; i < 16; i++) if (v[i]) { hi = 1; break; }
        if (!hi) break;

        uint32_t h[8];
        for (int i = 0; i < 8; i++) { h[i] = (uint32_t)v[8 + i]; v[8 + i] = 0; }
        for (int i = 0; i < 8; i++) {                /* v += high*R0 */
            int64_t hi64 = (int64_t)h[i];
            v[0 + i] += hi64;                        /* + high       */
            v[3 + i] -= hi64;                        /* - high<<96   */
            v[6 + i] -= hi64;                        /* - high<<192  */
            v[7 + i] += hi64;                        /* + high<<224  */
        }
    }

    for (int i = 0; i < 8; i++) r[i] = (uint32_t)v[i];   /* now < 2^256, >= 0 */
    if (cmp8(r, P) >= 0) sub_P(r);                       /* < 2^256 < 2p -> one subtract */
}

void fe_mul(fe *r, const fe *a, const fe *b)
{
    uint32_t prod[16];
    mul8(prod, a->v, b->v);
    fe_reduce(r->v, prod);
}

void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

void fe_inv(fe *r, const fe *a)
{
    /* Fermat: a^(p-2) mod p, exponent p-2 in little-endian limbs. fe_inv(0)=0. */
    static const uint32_t E[8] = {
        0xFFFFFFFDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
        0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
    };
    fe x; fe_set_u32(&x, 1);
    for (int i = 255; i >= 0; i--) {
        fe_sqr(&x, &x);
        if ((E[i >> 5] >> (i & 31)) & 1) fe_mul(&x, &x, a);
    }
    fe_copy(r, &x);
}
