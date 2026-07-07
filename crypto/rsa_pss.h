/* RSASSA-PSS signature verification (RFC 8017 §8.1.2 / §9.1.2) — v1.
 *
 * SHA-256 as both the message hash and the MGF1 hash, salt length == hash length
 * — i.e. TLS 1.3's rsa_pss_rsae_sha256. Verification only: no signing, no private
 * keys. Pure math over crypto/{rsa,mgf1,sha256}; knows nothing about certificates
 * or TLS. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Verify an RSA-PSS signature. `hash` is SHA-256 of the signed message (32
 * bytes); n/e are the public key (big-endian). Returns 0 if valid, -1 otherwise. */
int rsa_pss_sha256_verify(const uint8_t *n, size_t nlen,
                          const uint8_t *e, size_t elen,
                          const uint8_t *sig, size_t siglen,
                          const uint8_t hash[32]);
