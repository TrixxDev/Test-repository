/* HMAC-SHA256 (RFC 2104). The MAC used everywhere in TLS / HKDF / tokens.
 * Portable + freestanding, like sha256.h. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA256_LEN 32

/* Compute HMAC-SHA256(key, msg) -> out[32]. */
void hmac_sha256(const void *key, size_t keylen,
                 const void *msg, size_t msglen,
                 uint8_t out[HMAC_SHA256_LEN]);
