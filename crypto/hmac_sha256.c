/* HMAC-SHA256 (RFC 2104) — see hmac_sha256.h. */
#include "hmac_sha256.h"
#include "sha256.h"

void hmac_sha256(const void *key, size_t keylen,
                 const void *msg, size_t msglen,
                 uint8_t out[HMAC_SHA256_LEN])
{
    uint8_t k[SHA256_BLOCK_LEN];                /* the key, padded to the block size */
    uint8_t khash[SHA256_DIGEST_LEN];
    const uint8_t *kp = (const uint8_t *)key;

    if (keylen > SHA256_BLOCK_LEN) {            /* long key -> use its hash */
        sha256(key, keylen, khash);
        kp = khash;
        keylen = SHA256_DIGEST_LEN;
    }
    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++)
        k[i] = i < keylen ? kp[i] : 0;

    uint8_t ipad[SHA256_BLOCK_LEN], opad[SHA256_BLOCK_LEN];
    for (int i = 0; i < SHA256_BLOCK_LEN; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_ctx c;
    uint8_t inner[SHA256_DIGEST_LEN];
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_LEN);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_LEN);
    sha256_update(&c, inner, SHA256_DIGEST_LEN);
    sha256_final(&c, out);
}
