/* HKDF — HMAC-based Key Derivation Function (RFC 5869) over HMAC-SHA256.
 * This is the heart of the TLS 1.3 key schedule: once Extract/Expand exist, most
 * of the handshake's secret derivation becomes a mechanical sequence of calls.
 * Portable + freestanding like the rest of crypto/ (only <stdint.h>/<stddef.h>,
 * no allocation, no OS calls). */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define HKDF_HASH_LEN 32          /* SHA-256 output length */
#define HKDF_MAX_INFO 512         /* bound on info for the freestanding buffer */

/* HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
 * If salt is NULL or saltlen is 0, a string of HKDF_HASH_LEN zero bytes is used
 * (per RFC 5869 §2.2). */
void hkdf_extract(const void *salt, size_t saltlen,
                  const void *ikm, size_t ikmlen,
                  uint8_t prk[HKDF_HASH_LEN]);

/* HKDF-Expand: OKM = T(1) | T(2) | ... truncated to len, where
 * T(i) = HMAC-SHA256(PRK, T(i-1) | info | i) and T(0) is empty (RFC 5869 §2.3).
 * Returns 0 on success, -1 if len > 255*HKDF_HASH_LEN or infolen > HKDF_MAX_INFO. */
int hkdf_expand(const uint8_t prk[HKDF_HASH_LEN],
                const void *info, size_t infolen,
                uint8_t *okm, size_t len);
