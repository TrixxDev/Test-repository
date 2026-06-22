/* Poly1305 (RFC 8439 §2.5) — see poly1305.h.
 *
 * Arithmetic is mod 2^130-5 with the accumulator held in five 26-bit limbs
 * (the "poly1305-donna-32" representation), so it needs only 32x32->64 bit
 * multiplies and never a 128-bit type — portable to plain i686. */
#include "poly1305.h"

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;  p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
}

void poly1305_auth(uint8_t tag[POLY1305_TAG_LEN],
                   const uint8_t *msg, size_t len,
                   const uint8_t key[POLY1305_KEY_LEN])
{
    /* r = key[0..15], clamped per RFC (mask off the high bits of each word). */
    uint32_t r0 = (rd32(key +  0)     ) & 0x3ffffff;
    uint32_t r1 = (rd32(key +  3) >> 2) & 0x3ffff03;
    uint32_t r2 = (rd32(key +  6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (rd32(key +  9) >> 6) & 0x3f03fff;
    uint32_t r4 = (rd32(key + 12) >> 8) & 0x00fffff;

    /* precomputed r1..r4 * 5 for the reduction step */
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;   /* accumulator */

    uint32_t pad0 = rd32(key + 16), pad1 = rd32(key + 20);
    uint32_t pad2 = rd32(key + 24), pad3 = rd32(key + 28);    /* s = key[16..31] */

    uint8_t block[16];
    while (len > 0) {
        size_t n = len < 16 ? len : 16;
        const uint8_t *m;
        uint32_t hibit;

        if (n == 16) {                  /* full block: append the 2^128 bit */
            m = msg;
            hibit = (1u << 24);
        } else {                        /* final partial block: copy, set the */
            for (size_t i = 0; i < n; i++)  block[i] = msg[i];   /* 1 byte after */
            block[n] = 1;                                        /* the message, */
            for (size_t i = n + 1; i < 16; i++) block[i] = 0;    /* zero-pad     */
            m = block;
            hibit = 0;                  /* the high bit is already in the buffer */
        }

        /* h += m */
        h0 += (rd32(m +  0)     ) & 0x3ffffff;
        h1 += (rd32(m +  3) >> 2) & 0x3ffffff;
        h2 += (rd32(m +  6) >> 4) & 0x3ffffff;
        h3 += (rd32(m +  9) >> 6) & 0x3ffffff;
        h4 += (rd32(m + 12) >> 8) | hibit;

        /* h *= r (schoolbook, folding the 2^130 overflow back in via *5) */
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        /* partial carry/reduce back into 26-bit limbs */
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = (h0 >> 26); h0 = h0 & 0x3ffffff;
        h1 += c;

        msg += n;
        len -= n;
    }

    /* fully carry h */
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* compute h + -p (i.e. h + 5, dropping bit 130) */
    uint32_t g0, g1, g2, g3, g4;
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);

    /* select g (= h - p) if h >= p, else h — branchlessly */
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* repack the five 26-bit limbs into four 32-bit words (mod 2^128) */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + s) mod 2^128 */
    uint64_t f;
    f = (uint64_t)h0 + pad0            ; h0 = (uint32_t)f;
    f = (uint64_t)h1 + pad1 + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + pad2 + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + pad3 + (f >> 32); h3 = (uint32_t)f;

    wr32(tag +  0, h0);
    wr32(tag +  4, h1);
    wr32(tag +  8, h2);
    wr32(tag + 12, h3);
}
