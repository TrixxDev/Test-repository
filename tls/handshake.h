/* TLS 1.3 handshake message layer (RFC 8446 §4) — client side, v1.
 *
 * Deterministic core only: build ClientHello, parse ServerHello, and the
 * Finished verify_data computation. No certificate parsing, no signature
 * verification, no extensions beyond what 1-RTT ECDHE needs (key_share,
 * supported_versions, supported_groups, signature_algorithms, SNI). Those are a
 * separate, later layer. Pure byte<->struct + the verified tls/ key schedule;
 * no networking, so it is exercised entirely on the host. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Handshake message types (RFC 8446 §4) */
#define TLS_HS_CLIENT_HELLO          1
#define TLS_HS_SERVER_HELLO          2
#define TLS_HS_ENCRYPTED_EXTENSIONS  8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_CERTIFICATE_VERIFY   15
#define TLS_HS_FINISHED             20

/* Named group / cipher suite we implement */
#define TLS_GROUP_X25519                  0x001d
#define TLS_CIPHER_CHACHA20_POLY1305_SHA256 0x1303

/* Build a ClientHello handshake message (4-byte header + body) into `out`.
 *   random[32]     : client random
 *   x25519_pub[32] : our ephemeral public key (the key_share)
 *   server_name    : SNI host (NUL-terminated), or NULL to omit
 * Returns the message length, or -1 on capacity error. The bytes are exactly
 * what must be fed to the transcript and wrapped in a handshake record. */
int tls_build_client_hello(uint8_t *out, size_t cap,
                           const uint8_t random[32],
                           const uint8_t x25519_pub[32],
                           const char *server_name);

/* Parse a ServerHello handshake message (4-byte header + body). On success sets
 * *cipher_suite and copies the server's x25519 key_share into
 * server_x25519_pub[32], returns 0. Returns -1 if malformed or if there is no
 * x25519 key_share. */
int tls_parse_server_hello(const uint8_t *msg, size_t len,
                           uint16_t *cipher_suite,
                           uint8_t server_x25519_pub[32]);

/* finished_key = HKDF-Expand-Label(base_secret, "finished", "", 32) (RFC 8446
 * §4.4.4). `base_secret` is the relevant handshake-traffic secret. */
void tls_finished_key(uint8_t out[32], const uint8_t base_secret[32]);

/* verify_data = HMAC-SHA256(finished_key, transcript_hash). */
void tls_finished_verify_data(uint8_t out[32], const uint8_t finished_key[32],
                              const uint8_t transcript_hash[32]);

/* Constant-time check of a peer's Finished. Returns 0 if verify_data matches the
 * value computed over transcript_hash, -1 otherwise. */
int tls_check_finished(const uint8_t finished_key[32],
                       const uint8_t transcript_hash[32],
                       const uint8_t received_verify_data[32]);
