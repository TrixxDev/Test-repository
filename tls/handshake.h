/* TLS 1.3 handshake message layer (RFC 8446 §4) — client side, v1; PSK
 * resumption — Phase 15.7.
 *
 * Deterministic core only: build ClientHello, parse ServerHello, and the
 * Finished verify_data computation. No certificate parsing, no signature
 * verification, no extensions beyond what 1-RTT ECDHE needs (key_share,
 * supported_versions, supported_groups, signature_algorithms, SNI), plus the
 * two resumption extensions (psk_key_exchange_modes, pre_shared_key) when a
 * cached session ticket is offered. Pure byte<->struct + the verified tls/
 * key schedule; no networking, so it is exercised entirely on the host. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "session.h"

/* Handshake message types (RFC 8446 §4) */
#define TLS_HS_CLIENT_HELLO          1
#define TLS_HS_SERVER_HELLO          2
#define TLS_HS_NEW_SESSION_TICKET    4
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
 *   resume         : a cached session ticket to offer for resumption
 *                    (pre_shared_key + psk_key_exchange_modes extensions,
 *                    RFC 8446 §4.2.11), or NULL for a full handshake only
 *   now_ms         : current time, for the ticket's obfuscated_ticket_age
 *                    (ignored if `resume` is NULL)
 *   binder_key[32] : Derive-Secret(early_secret, "res binder", "") -- the
 *                    caller has already derived this from `resume->psk`
 *                    (ignored if `resume` is NULL)
 * Returns the message length, or -1 on capacity error. The bytes are exactly
 * what must be fed to the transcript and wrapped in a handshake record. */
int tls_build_client_hello(uint8_t *out, size_t cap,
                           const uint8_t random[32],
                           const uint8_t x25519_pub[32],
                           const char *server_name,
                           const tls_session_ticket *resume,
                           uint64_t now_ms,
                           const uint8_t binder_key[32]);

/* Parse a ServerHello handshake message (4-byte header + body). On success sets
 * *cipher_suite and copies the server's x25519 key_share into
 * server_x25519_pub[32], returns 0. Returns -1 if malformed or if there is no
 * x25519 key_share. If `psk_selected` is non-NULL, *psk_selected is set to 1
 * if the ServerHello carries a pre_shared_key extension (selecting the one
 * PSK we ever offer, at index 0) and 0 otherwise. */
int tls_parse_server_hello(const uint8_t *msg, size_t len,
                           uint16_t *cipher_suite,
                           uint8_t server_x25519_pub[32],
                           int *psk_selected);

/* Parse a NewSessionTicket handshake message (4-byte header + body, RFC 8446
 * §4.6.1) into *out. Fills lifetime_secs/age_add/ticket/ticket_len; does NOT
 * fill out->obtained_ms or out->psk (the caller's job -- deriving the PSK
 * needs the connection's resumption_master_secret, which this layer doesn't
 * have). The ticket_nonce is copied to `nonce` (capacity `nonce_cap`) with
 * its length in *nonce_len, since it's needed to derive that PSK. Returns 0
 * on success, -1 if malformed or the ticket/nonce doesn't fit. */
int tls_parse_new_session_ticket(const uint8_t *msg, size_t len,
                                 tls_session_ticket *out,
                                 uint8_t *nonce, size_t nonce_cap, size_t *nonce_len);

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
