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
 * secret; `hello_hash` is Transcript-Hash(ClientHello..ServerHello). */
typedef struct {
    uint8_t early_secret[TLS_SECRET_LEN];
    uint8_t handshake_secret[TLS_SECRET_LEN];
    uint8_t master_secret[TLS_SECRET_LEN];
    uint8_t client_hs_traffic[TLS_SECRET_LEN];   /* client_handshake_traffic_secret */
    uint8_t server_hs_traffic[TLS_SECRET_LEN];   /* server_handshake_traffic_secret */
} tls_key_schedule;

/* Early Secret = HKDF-Extract(0, PSK). `psk` may be NULL (or psk_len 0), in
 * which case IKM is all zeros -- the full-handshake case (RFC 8446 §7.1). */
void tls_derive_early_secret(uint8_t early_secret[TLS_SECRET_LEN],
                             const uint8_t *psk, size_t psk_len);

/* Run the schedule from an already-computed Early Secret (RFC 8446 §7.1):
 *   Handshake Secret = HKDF-Extract(Derive-Secret(Early,"derived",""), ECDHE)
 *   client/server_hs_traffic = Derive-Secret(Handshake, "c/s hs traffic", hello_hash)
 *   Master Secret = HKDF-Extract(Derive-Secret(Handshake,"derived",""), 0)
 * This is the PSK-aware entry point (Phase 15.7): call tls_derive_early_secret
 * first with the offered PSK (or NULL for a full handshake), then this. */
void tls_key_schedule_derive_from_early(tls_key_schedule *ks,
                                        const uint8_t early_secret[TLS_SECRET_LEN],
                                        const uint8_t ecdhe[TLS_SECRET_LEN],
                                        const uint8_t hello_hash[TLS_SECRET_LEN]);

/* Convenience wrapper for the full (non-PSK) handshake: identical to calling
 * tls_derive_early_secret(es, NULL, 0) then tls_key_schedule_derive_from_early.
 * Kept as its own entry point so every existing caller is unaffected by 15.7. */
void tls_key_schedule_derive(tls_key_schedule *ks,
                             const uint8_t ecdhe[TLS_SECRET_LEN],
                             const uint8_t hello_hash[TLS_SECRET_LEN]);

/* binder_key = Derive-Secret(early_secret, "res binder", "") (RFC 8446 §7.1,
 * the resumption-PSK binder -- "ext binder" is for externally provisioned
 * PSKs, which Aurora doesn't support). */
void tls_derive_binder_key(uint8_t binder_key[TLS_SECRET_LEN],
                           const uint8_t early_secret[TLS_SECRET_LEN]);

/* resumption_master_secret = Derive-Secret(Master Secret, "res master",
 * Transcript-Hash(ClientHello..client Finished)) (RFC 8446 §7.1). Computed
 * once a handshake reaches CONNECTED, so a later NewSessionTicket's PSK can
 * be derived from it. */
void tls_derive_resumption_master_secret(uint8_t out[TLS_SECRET_LEN],
                                         const uint8_t master_secret[TLS_SECRET_LEN],
                                         const uint8_t transcript_hash_cf[TLS_SECRET_LEN]);

/* A ticket's PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
 * ticket_nonce, Hash.length) (RFC 8446 §4.6.1). */
void tls_derive_ticket_psk(uint8_t psk_out[TLS_SECRET_LEN],
                           const uint8_t resumption_master_secret[TLS_SECRET_LEN],
                           const uint8_t *ticket_nonce, size_t nonce_len);

/* Derive an AEAD write key + IV from a traffic secret (HKDF-Expand-Label with
 * labels "key" and "iv", empty context). keylen is 32 for ChaCha20-Poly1305. */
void tls_traffic_keys(const uint8_t traffic_secret[TLS_SECRET_LEN],
                      uint8_t *key, size_t keylen,
                      uint8_t *iv, size_t ivlen);
