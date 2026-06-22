/* TLS 1.3 key schedule (RFC 8446 §7.1) for the SHA-256 / X25519 path.
 *
 * This is the deterministic key algebra that turns the ECDHE shared secret plus
 * the handshake transcript into traffic secrets and AEAD keys. It is pure
 * protocol logic over the verified crypto/ primitives — HKDF-Expand-Label and
 * Derive-Secret are TLS helpers here, NOT crypto primitives (they wrap
 * hkdf_expand). No networking, no record framing. Part of the tls/ layer. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define TLS_SECRET_LEN 32       /* SHA-256 output / secret length */

/* HKDF-Expand-Label (RFC 8446 §7.1):
 *   HkdfLabel = uint16(length) | opaque "tls13 "+label<7..255> | opaque context<0..255>
 *   out[0..outlen) = HKDF-Expand(secret, HkdfLabel, outlen). */
void tls_hkdf_expand_label(uint8_t *out, size_t outlen,
                           const uint8_t secret[TLS_SECRET_LEN],
                           const char *label,
                           const uint8_t *context, size_t ctxlen);

/* Derive-Secret(secret, label, messages) =
 *   HKDF-Expand-Label(secret, label, Transcript-Hash(messages), Hash.length).
 * `thash` is the already-computed transcript hash for `messages`. */
void tls_derive_secret(uint8_t out[TLS_SECRET_LEN],
                       const uint8_t secret[TLS_SECRET_LEN],
                       const char *label,
                       const uint8_t thash[TLS_SECRET_LEN]);

/* The 1-RTT secret schedule (RFC 8446 §7.1). `ecdhe` is the X25519 shared
 * secret; `hello_hash` is Transcript-Hash(ClientHello..ServerHello). PSK is
 * absent (the early-secret IKM is all zeros). */
typedef struct {
    uint8_t early_secret[TLS_SECRET_LEN];
    uint8_t handshake_secret[TLS_SECRET_LEN];
    uint8_t master_secret[TLS_SECRET_LEN];
    uint8_t client_hs_traffic[TLS_SECRET_LEN];   /* client_handshake_traffic_secret */
    uint8_t server_hs_traffic[TLS_SECRET_LEN];   /* server_handshake_traffic_secret */
} tls_key_schedule;

void tls_key_schedule_derive(tls_key_schedule *ks,
                             const uint8_t ecdhe[TLS_SECRET_LEN],
                             const uint8_t hello_hash[TLS_SECRET_LEN]);

/* Derive an AEAD write key + IV from a traffic secret (HKDF-Expand-Label with
 * labels "key" and "iv", empty context). keylen is 32 for ChaCha20-Poly1305. */
void tls_traffic_keys(const uint8_t traffic_secret[TLS_SECRET_LEN],
                      uint8_t *key, size_t keylen,
                      uint8_t *iv, size_t ivlen);
