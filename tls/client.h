/* TLS 1.3 client handshake state machine (RFC 8446 §4) — FSM core, v1.
 *
 * A deterministic, event-driven engine over *plaintext* handshake messages: it
 * owns the transcript, the key schedule, and the (state, key_phase) pair, and it
 * emits the messages the client must send (ClientHello, Finished). It does NOT
 * touch the network or the record layer — record decryption / plaintext-vs-
 * encrypted gating is the caller's job (the record-binding layer), so an AEAD
 * failure never reaches this FSM. Certificates are not validated yet (v1).
 *
 * Determinism: the ephemeral key and client random are supplied by the caller,
 * so a given event sequence always produces the same bytes — it can be replayed
 * as a test-vector machine with no entropy or sockets. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "transcript.h"
#include "key_schedule.h"

/* Protocol state — what message we expect next (RFC 8446 §A.1, client view). */
typedef enum {
    TLS_ST_START = 0,
    TLS_ST_WAIT_SH,
    TLS_ST_WAIT_EE,
    TLS_ST_WAIT_CERT,
    TLS_ST_WAIT_CV,
    TLS_ST_WAIT_FINISHED,
    TLS_ST_CONNECTED,
    TLS_ST_ERROR
} tls_state;

/* Cryptographic phase — which traffic keys the record layer should be using.
 * Kept separate from `state`: the record-binding layer switches keys on phase
 * changes, independent of which handshake message is expected next. */
typedef enum {
    TLS_PHASE_EARLY = 0,        /* ClientHello is plaintext */
    TLS_PHASE_HANDSHAKE,        /* after ServerHello: handshake traffic keys */
    TLS_PHASE_APPLICATION       /* after server Finished: application traffic keys */
} tls_key_phase;

typedef struct {
    tls_state      state;
    tls_key_phase  phase;
    tls_transcript transcript;

    uint8_t  priv[32], pub[32];          /* our ephemeral x25519 key pair */
    uint8_t  client_random[32];
    char     server_name[256];
    uint16_t cipher_suite;               /* negotiated (from ServerHello) */

    tls_key_schedule ks;                 /* early/handshake/master + hs traffic */
    uint8_t client_hs_finished_key[32];
    uint8_t server_hs_finished_key[32];

    uint8_t client_ap_secret[32];        /* application traffic secrets, set at */
    uint8_t server_ap_secret[32];        /* CONNECTED (RFC 8446 §7.1)            */
} tls_client;

/* Initialize. `ephemeral_priv` and `client_random` make the engine fully
 * deterministic (supply real randomness in production). */
void tls_client_init(tls_client *c, const char *server_name,
                     const uint8_t ephemeral_priv[32],
                     const uint8_t client_random[32]);

/* Emit the initial ClientHello (plaintext handshake message) into `out`.
 * Returns its length or -1. START -> WAIT_SH. */
int tls_client_start(tls_client *c, uint8_t *out, size_t cap);

/* Feed one plaintext handshake message (4-byte header + body). On the server's
 * Finished this emits the client's Finished into `out` (its length in *out_len;
 * 0 when nothing is emitted). Returns 0 on success, -1 on protocol error (which
 * also moves the FSM to TLS_ST_ERROR). */
int tls_client_recv_handshake(tls_client *c, const uint8_t *msg, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len);

static inline int tls_client_connected(const tls_client *c) { return c->state == TLS_ST_CONNECTED; }
