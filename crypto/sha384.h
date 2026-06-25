/* SHA-384 and SHA-512 (FIPS 180-4). Portable, freestanding: depends only on
 * <stdint.h> / <stddef.h>, so the same source compiles for the host test, user
 * space and the kernel. No dynamic allocation, no OS calls.
 *
 * SHA-384 is SHA-512 with a distinct initial state and the digest truncated to
 * the leftmost 48 bytes; both run the identical 64-bit, 80-round compression
 * core. SHA-512 is exposed too -- it is the core SHA-384 truncates, and testing
 * it directly (NIST KATs) validates the compression independent of truncation.
 *
 * Aurora needs SHA-384 for ECDSA-P384 / ecdsa-with-SHA384 certificate chains and
 * the ecdsa_secp384r1_sha384 TLS signature scheme. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define SHA384_DIGEST_LEN 48
#define SHA512_DIGEST_LEN 64
#define SHA512_BLOCK_LEN  128

typedef struct {
    uint64_t state[8];
    uint64_t total_len;     /* message bytes processed so far */
    uint8_t  buf[128];
    size_t   buflen;        /* bytes currently buffered (< 128) */
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha384_init(sha512_ctx *c);                /* same ctx, SHA-384 initial state */
void sha512_update(sha512_ctx *c, const void *data, size_t len);
void sha512_final(sha512_ctx *c, uint8_t out[SHA512_DIGEST_LEN]);
void sha384_final(sha512_ctx *c, uint8_t out[SHA384_DIGEST_LEN]);   /* leftmost 48 */

/* One-shot convenience: digest `len` bytes of `data` into `out`. */
void sha512(const void *data, size_t len, uint8_t out[SHA512_DIGEST_LEN]);
void sha384(const void *data, size_t len, uint8_t out[SHA384_DIGEST_LEN]);
