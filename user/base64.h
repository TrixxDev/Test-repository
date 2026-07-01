/* user/base64.h — RFC 4648 base64 encoding, for HTTP Basic auth (Phase
 * 16.2): "Authorization: Basic " + base64("user:pass").
 *
 * Freestanding, like url.c and cookiejar.c: only <stddef.h>, no libc, no
 * allocation, so the exact same object links into user/httpsget and a host
 * test binary. Encode-only -- httpsget never needs to decode base64. */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* Exact encoded length for `inlen` input bytes, padding included, so a
 * caller can size its output buffer before calling base64_encode(). */
int base64_encoded_len(int inlen);

/* Encode `inlen` bytes of `in` into base64 (standard alphabet, '='-padded).
 * Writes into `out` (capacity `outcap`); NOT null-terminated, matching the
 * rest of httpsget's header-building helpers. Returns the encoded length,
 * or -1 if `outcap` is smaller than base64_encoded_len(inlen). */
int base64_encode(const uint8_t *in, int inlen, char *out, int outcap);
