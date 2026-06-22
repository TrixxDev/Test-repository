/* ChaCha20 (RFC 8439) — see chacha20.h. */
#include "chacha20.h"

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl(*d, 16);
    *c += *d; *b ^= *c; *b = rotl(*b, 12);
    *a += *b; *d ^= *a; *d = rotl(*d, 8);
    *c += *d; *b ^= *c; *b = rotl(*b, 7);
}

/* The ChaCha20 block function: 20 rounds (10 column + 10 diagonal), then add the
 * original input state, then serialize little-endian (RFC 8439 §2.3). */
static void chacha20_core(const uint32_t in[16], uint8_t out[CHACHA20_BLOCK_LEN])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];

    for (int i = 0; i < 10; i++) {
        chacha20_quarterround(&x[0], &x[4], &x[8],  &x[12]);   /* columns  */
        chacha20_quarterround(&x[1], &x[5], &x[9],  &x[13]);
        chacha20_quarterround(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarterround(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarterround(&x[0], &x[5], &x[10], &x[15]);   /* diagonals */
        chacha20_quarterround(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarterround(&x[2], &x[7], &x[8],  &x[13]);
        chacha20_quarterround(&x[3], &x[4], &x[9],  &x[14]);
    }

    for (int i = 0; i < 16; i++) x[i] += in[i];
    for (int i = 0; i < 16; i++) {
        out[i*4+0] = (uint8_t)(x[i]);
        out[i*4+1] = (uint8_t)(x[i] >> 8);
        out[i*4+2] = (uint8_t)(x[i] >> 16);
        out[i*4+3] = (uint8_t)(x[i] >> 24);
    }
}

void chacha20_init(chacha20_ctx *c, const uint8_t key[CHACHA20_KEY_LEN],
                   const uint8_t nonce[CHACHA20_NONCE_LEN], uint32_t counter)
{
    c->state[0] = 0x61707865;   /* "expa" */
    c->state[1] = 0x3320646e;   /* "nd 3" */
    c->state[2] = 0x79622d32;   /* "2-by" */
    c->state[3] = 0x6b206574;   /* "te k" */
    for (int i = 0; i < 8; i++) c->state[4 + i]  = rd32le(key   + i*4);
    c->state[12] = counter;
    for (int i = 0; i < 3; i++) c->state[13 + i] = rd32le(nonce + i*4);
}

void chacha20_block(chacha20_ctx *c, uint8_t out[CHACHA20_BLOCK_LEN])
{
    chacha20_core(c->state, out);
    c->state[12]++;             /* advance the 32-bit block counter */
}

void chacha20_xor(chacha20_ctx *c, const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[CHACHA20_BLOCK_LEN];
    size_t off = 0;
    while (off < len) {
        chacha20_block(c, ks);
        size_t n = len - off;
        if (n > CHACHA20_BLOCK_LEN) n = CHACHA20_BLOCK_LEN;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        off += n;
    }
}
