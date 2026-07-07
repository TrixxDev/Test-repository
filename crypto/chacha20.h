/* ChaCha20 stream cipher (RFC 8439). Chosen before AES: on i686 with no AES-NI
 * it is simpler and constant-time by construction, and pairs with Poly1305 into
 * TLS_CHACHA20_POLY1305_SHA256 — a full HTTPS path with no AES at all.
 * Portable + freestanding like the rest of crypto/ (only <stdint.h>/<stddef.h>,
 * no allocation, no OS calls). */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_LEN   32
#define CHACHA20_NONCE_LEN 12
#define CHACHA20_BLOCK_LEN 64

typedef struct {
    uint32_t state[16];     /* constants | key | counter | nonce */
} chacha20_ctx;

/* The quarter-round (RFC 8439 §2.1). Exposed so it can be verified in isolation
 * against the RFC's lowest-level test vector — a bug here invalidates everything
 * above it. */
void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);

/* Set up state from a 256-bit key, 96-bit nonce and a 32-bit block counter. */
void chacha20_init(chacha20_ctx *c, const uint8_t key[CHACHA20_KEY_LEN],
                   const uint8_t nonce[CHACHA20_NONCE_LEN], uint32_t counter);

/* Produce one 64-byte keystream block and advance the block counter. */
void chacha20_block(chacha20_ctx *c, uint8_t out[CHACHA20_BLOCK_LEN]);

/* XOR `len` bytes of `in` with the keystream into `out` (in==out is fine).
 * Encryption and decryption are the same operation. */
void chacha20_xor(chacha20_ctx *c, const uint8_t *in, uint8_t *out, size_t len);
