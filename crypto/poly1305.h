/* Poly1305 one-time authenticator (RFC 8439 §2.5). A pure primitive: message +
 * one-time 32-byte key -> 16-byte tag. Deliberately NOT shaped for TLS — the
 * AEAD layer on top supplies the one-time key (derived per record) and the
 * AAD/length framing. Portable + freestanding like the rest of crypto/.
 *
 * SECURITY: the key is one-time. Never authenticate two messages with the same
 * key — Poly1305 is only secure when each (r,s) key is used exactly once. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define POLY1305_TAG_LEN 16
#define POLY1305_KEY_LEN 32

/* Streaming context. The AEAD construction MACs several non-contiguous spans
 * (AAD, padding, ciphertext, padding, lengths) without ever copying them into
 * one big buffer, so it needs init/update/final rather than only the one-shot. */
typedef struct {
    uint32_t r[5];          /* clamped key, 26-bit limbs */
    uint32_t h[5];          /* accumulator, 26-bit limbs */
    uint32_t pad[4];        /* s = key[16..31] */
    uint8_t  buffer[16];    /* partial block carried between updates */
    size_t   leftover;      /* bytes currently in buffer (< 16) */
} poly1305_ctx;

void poly1305_init(poly1305_ctx *st, const uint8_t key[POLY1305_KEY_LEN]);
void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t len);
void poly1305_final(poly1305_ctx *st, uint8_t tag[POLY1305_TAG_LEN]);

/* One-shot: tag = Poly1305(msg[0..len), key). key is r (16 bytes) || s (16). */
void poly1305_auth(uint8_t tag[POLY1305_TAG_LEN],
                   const uint8_t *msg, size_t len,
                   const uint8_t key[POLY1305_KEY_LEN]);
