/* MGF1-SHA256 — see mgf1.h. */
#include "mgf1.h"
#include "sha256.h"

void mgf1_sha256(const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen)
{
    uint32_t counter = 0;
    size_t done = 0;
    while (done < outlen) {
        uint8_t c[4] = { (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                         (uint8_t)(counter >> 8),  (uint8_t)counter };
        sha256_ctx h;
        sha256_init(&h);
        sha256_update(&h, seed, seedlen);
        sha256_update(&h, c, 4);
        uint8_t block[SHA256_DIGEST_LEN];
        sha256_final(&h, block);

        size_t n = outlen - done;
        if (n > SHA256_DIGEST_LEN) n = SHA256_DIGEST_LEN;
        for (size_t i = 0; i < n; i++) out[done + i] = block[i];
        done += n;
        counter++;
    }
}
