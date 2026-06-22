/* SHA-256 (FIPS 180-4). Portable, freestanding: depends only on <stdint.h> /
 * <stddef.h>, so the same source compiles for the host test, user space and the
 * kernel. No dynamic allocation, no OS calls. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN  64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;        /* message length processed so far, in bits */
    uint8_t  buf[64];
    size_t   buflen;        /* bytes currently buffered (< 64) */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);

/* One-shot convenience: digest `len` bytes of `data` into `out`. */
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);
