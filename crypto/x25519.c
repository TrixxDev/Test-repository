/* X25519 (RFC 7748) — see x25519.h.
 *
 * Field elements are 16 signed limbs of radix 2^16 (mod 2^255-19). The structure
 * follows the well-known compact public-domain reference (TweetNaCl): a constant
 * -time Montgomery ladder with branch-free conditional swaps, so the secret
 * scalar never influences control flow or memory access patterns. */
#include "x25519.h"

typedef int64_t fe[16];                 /* field element mod 2^255-19 */

static const fe f121665 = {0xDB41, 1};  /* (486662-2)/4 = 121665 */

static void fe_copy(fe o, const fe a) { for (int i = 0; i < 16; i++) o[i] = a[i]; }
static void fe_add(fe o, const fe a, const fe b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void fe_sub(fe o, const fe a, const fe b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

/* normalize limbs back into [0,2^16) with the 2^255-19 wrap folded into limb 0 */
static void fe_carry(fe o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

/* branch-free conditional swap of p and q when b == 1 */
static void fe_cswap(fe p, fe q, int b)
{
    int64_t c = ~((int64_t)b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_mul(fe o, const fe a, const fe b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];   /* reduce 2^256 -> 2^0 */
    for (int i = 0; i < 16; i++) o[i] = t[i];
    fe_carry(o);
    fe_carry(o);
}

static void fe_sq(fe o, const fe a) { fe_mul(o, a, a); }

/* o = a^(p-2) mod p — modular inverse via Fermat's little theorem */
static void fe_inv(fe o, const fe a)
{
    fe c;
    fe_copy(c, a);
    for (int i = 253; i >= 0; i--) {
        fe_sq(c, c);
        if (i != 2 && i != 4) fe_mul(c, c, a);
    }
    fe_copy(o, c);
}

static void fe_unpack(fe o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;                    /* clear the top bit (u < 2^255) */
}

static void fe_pack(uint8_t *o, const fe n)
{
    fe t, m;
    fe_copy(t, n);
    fe_carry(t); fe_carry(t); fe_carry(t);
    for (int j = 0; j < 2; j++) {       /* conditional subtract of p, twice */
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        fe_cswap(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) { o[2 * i] = t[i] & 0xff; o[2 * i + 1] = (uint8_t)(t[i] >> 8); }
}

void x25519(uint8_t out[X25519_KEY_LEN],
            const uint8_t scalar[X25519_KEY_LEN],
            const uint8_t point[X25519_KEY_LEN])
{
    uint8_t e[32];
    for (int i = 0; i < 32; i++) e[i] = scalar[i];
    e[0]  &= 248;                       /* clamp (RFC 7748 §5) */
    e[31] = (e[31] & 127) | 64;

    fe x, a, b, c, d, ee, f;
    fe_unpack(x, point);
    for (int i = 0; i < 16; i++) { b[i] = x[i]; a[i] = c[i] = d[i] = 0; }
    a[0] = d[0] = 1;                    /* (x2,z2)=(1,0), (x3,z3)=(u,1) */

    for (int i = 254; i >= 0; i--) {
        int bit = (e[i >> 3] >> (i & 7)) & 1;
        fe_cswap(a, b, bit);
        fe_cswap(c, d, bit);
        fe_add(ee, a, c);
        fe_sub(a, a, c);
        fe_add(c, b, d);
        fe_sub(b, b, d);
        fe_sq(d, ee);
        fe_sq(f, a);
        fe_mul(a, c, a);
        fe_mul(c, b, ee);
        fe_add(ee, a, c);
        fe_sub(a, a, c);
        fe_sq(b, a);
        fe_sub(c, d, f);
        fe_mul(a, c, f121665);
        fe_add(a, a, d);
        fe_mul(c, c, a);
        fe_mul(a, d, f);
        fe_mul(d, b, x);
        fe_sq(b, ee);
        fe_cswap(a, b, bit);
        fe_cswap(c, d, bit);
    }

    fe_inv(c, c);                       /* x2 * z2^-1 */
    fe_mul(a, a, c);
    fe_pack(out, a);
}

void x25519_base(uint8_t out[X25519_KEY_LEN], const uint8_t scalar[X25519_KEY_LEN])
{
    static const uint8_t basepoint[32] = {9};
    x25519(out, scalar, basepoint);
}
