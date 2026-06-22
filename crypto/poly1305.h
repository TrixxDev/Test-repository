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

/* tag = Poly1305(msg[0..len), key). key is r (16 bytes) || s (16 bytes). */
void poly1305_auth(uint8_t tag[POLY1305_TAG_LEN],
                   const uint8_t *msg, size_t len,
                   const uint8_t key[POLY1305_KEY_LEN]);
