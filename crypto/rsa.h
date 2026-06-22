/* RSA public-key operations (RFC 8017) — v1, verification only.
 *
 * Pure math over crypto/bignum: a public-exponent modexp plus PKCS#1 v1.5
 * signature verification. It knows the PKCS#1 envelope but NOTHING about
 * certificates or which hash is in use — the caller supplies the DER DigestInfo.
 * No allocation; freestanding. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define RSA_MAX_BYTES 512   /* modulus up to RSA-4096 */

/* RSA public-key operation: out = (in ^ e) mod n, big-endian, written as exactly
 * `nlen` bytes (left-padded with zeros). All inputs are big-endian byte strings.
 * Returns nlen on success, -1 on error (in must be < n). */
int rsa_public(const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen,
               const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* RSA PKCS#1 v1.5 signature verification (RFC 8017 §8.2.2, construct-and-compare):
 * recover EM = sig^e mod n and check it equals
 *   0x00 || 0x01 || PS(0xFF, at least 8) || 0x00 || digestinfo
 * by rebuilding the expected encoding and comparing — no parsing of the recovered
 * block, so there is no room for a forged DigestInfo or short padding. The caller
 * supplies the full DER DigestInfo (algorithm + digest). Returns 0 if valid. */
int rsa_pkcs1_v15_verify(const uint8_t *n, size_t nlen,
                         const uint8_t *e, size_t elen,
                         const uint8_t *sig, size_t siglen,
                         const uint8_t *digestinfo, size_t dilen);
