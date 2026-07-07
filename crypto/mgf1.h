/* MGF1 mask generation function (RFC 8017 §B.2.1) over SHA-256.
 *
 * A pure primitive: hash the seed concatenated with a 32-bit big-endian counter,
 * 0,1,2,..., and concatenate the digests until `outlen` bytes are produced. Used
 * by RSA-PSS. Freestanding, no allocation. */
#pragma once
#include <stdint.h>
#include <stddef.h>

void mgf1_sha256(const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen);
