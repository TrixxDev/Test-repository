/* AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) — see chacha20poly1305.h. */
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"

static const uint8_t zeros[16] = {0};

static void wr64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* RFC 8439 §2.6: the one-time Poly1305 key is the first 32 bytes of the
 * ChaCha20 keystream for this (key, nonce) at block counter 0. */
static void poly_key_gen(uint8_t otk[32], const uint8_t key[32], const uint8_t nonce[12])
{
    chacha20_ctx c;
    uint8_t block[CHACHA20_BLOCK_LEN];
    chacha20_init(&c, key, nonce, 0);
    chacha20_block(&c, block);
    for (int i = 0; i < 32; i++) otk[i] = block[i];
}

/* Tag = Poly1305_otk( aad | pad16 | ciphertext | pad16 | le64(aadlen) | le64(ctlen) ). */
static void aead_mac(uint8_t tag[16], const uint8_t otk[32],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t ctlen)
{
    poly1305_ctx p;
    uint8_t lenblock[16];

    poly1305_init(&p, otk);
    poly1305_update(&p, aad, aadlen);
    poly1305_update(&p, zeros, (16 - (aadlen & 15)) & 15);
    poly1305_update(&p, ct, ctlen);
    poly1305_update(&p, zeros, (16 - (ctlen & 15)) & 15);
    wr64le(lenblock + 0, aadlen);
    wr64le(lenblock + 8, ctlen);
    poly1305_update(&p, lenblock, 16);
    poly1305_final(&p, tag);
}

void chacha20poly1305_seal(uint8_t *ct, uint8_t tag[CHACHA20POLY1305_TAG_LEN],
                           const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                           const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN],
                           const uint8_t *aad, size_t aadlen,
                           const uint8_t *pt, size_t ptlen)
{
    uint8_t otk[32];
    chacha20_ctx c;

    poly_key_gen(otk, key, nonce);
    chacha20_init(&c, key, nonce, 1);       /* message encryption starts at block 1 */
    chacha20_xor(&c, pt, ct, ptlen);
    aead_mac(tag, otk, aad, aadlen, ct, ptlen);
}

int chacha20poly1305_open(uint8_t *pt,
                          const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                          const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN],
                          const uint8_t *aad, size_t aadlen,
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t tag[CHACHA20POLY1305_TAG_LEN])
{
    uint8_t otk[32], expected[16];
    chacha20_ctx c;

    poly_key_gen(otk, key, nonce);
    aead_mac(expected, otk, aad, aadlen, ct, ctlen);

    /* constant-time tag comparison — verify before producing any plaintext */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(expected[i] ^ tag[i]);
    if (diff != 0) return -1;               /* forged/tampered: refuse to decrypt */

    chacha20_init(&c, key, nonce, 1);
    chacha20_xor(&c, ct, pt, ctlen);
    return 0;
}
