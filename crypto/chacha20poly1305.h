/* AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) — authenticated encryption with
 * associated data. This is the exact construction used by the TLS 1.3 cipher
 * suite TLS_CHACHA20_POLY1305_SHA256, so once the TLS record layer exists it
 * encrypts/decrypts records by calling straight into seal/open.
 * Portable + freestanding like the rest of crypto/. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define CHACHA20POLY1305_KEY_LEN   32
#define CHACHA20POLY1305_NONCE_LEN 12
#define CHACHA20POLY1305_TAG_LEN   16

/* Seal: encrypt ptlen bytes (pt -> ct, same length) and produce the 16-byte
 * authentication tag over aad + ct. ct may alias pt. */
void chacha20poly1305_seal(uint8_t *ct, uint8_t tag[CHACHA20POLY1305_TAG_LEN],
                           const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                           const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN],
                           const uint8_t *aad, size_t aadlen,
                           const uint8_t *pt, size_t ptlen);

/* Open: verify the tag FIRST; only if it matches, decrypt ct -> pt (same
 * length) and return 0. On any mismatch return -1 and leave pt untouched, so a
 * forged or tampered record never yields plaintext. pt may alias ct. */
int chacha20poly1305_open(uint8_t *pt,
                          const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                          const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN],
                          const uint8_t *aad, size_t aadlen,
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t tag[CHACHA20POLY1305_TAG_LEN]);
