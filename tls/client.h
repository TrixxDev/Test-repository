/* TLS 1.3 client handshake state machine (RFC 8446 §4) — FSM core, v1.
 *
 * A deterministic, event-driven engine over *plaintext* handshake messages: it
 * owns the transcript, the key schedule, and the (state, key_phase) pair, and it
 * emits the messages the client must send (ClientHello, Finished). It does NOT
 * touch the network or the record layer — record decryption / plaintext-vs-
 * encrypted gating is the caller's job (the record-binding layer), so an AEAD
 * failure never reaches this FSM.
 *
 * Certificate trust is optional: if a trust store is installed (tls_client_set_
 * trust), the Certificate message is parsed and validated (chain + validity +
 * hostname) at WAIT_CERT, and a failure drives the FSM to ERROR. With no trust
 * store the certificate is still only transcript bytes (engine / test mode).
 * Proving the peer holds the private key (CertificateVerify) is a later step.
 *
 * Determinism: the ephemeral key and client random are supplied by the caller,
 * so a given event sequence always produces the same bytes — it can be replayed
 * as a test-vector machine with no entropy or sockets. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "transcript.h"
#include "key_schedule.h"
#include "cert.h"
#include "trace.h"
#include "session.h"

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

/* Why the FSM entered TLS_ST_ERROR — kept distinct so a live HTTPS failure is
 * easy to localize (a rejected certificate vs a forged signature vs a framing
 * error are very different problems). */
typedef enum {
    TLS_ERR_NONE = 0,
    TLS_ERR_PROTOCOL,           /* malformed/unexpected message, record or Finished */
    TLS_ERR_CERT,               /* certificate chain / validity / hostname rejected */
    TLS_ERR_AUTH                /* CertificateVerify failed: key ownership not proven */
} tls_error;

#define TLS_LEAF_SPKI_MAX 600   /* room for an RSA-4096 RSAPublicKey */

typedef struct {
    tls_state      state;
    tls_key_phase  phase;
    tls_transcript transcript;

    uint8_t  priv[32], pub[32];          /* our ephemeral x25519 key pair */
    uint8_t  client_random[32];
    char     server_name[256];
    uint16_t cipher_suite;               /* negotiated (from ServerHello) */
    uint16_t cv_scheme;                  /* CertificateVerify SignatureScheme accepted (0 = none) */

    tls_key_schedule ks;                 /* early/handshake/master + hs traffic */
    uint8_t client_hs_finished_key[32];
    uint8_t server_hs_finished_key[32];

    uint8_t client_ap_secret[32];        /* application traffic secrets, set at */
    uint8_t server_ap_secret[32];        /* CONNECTED (RFC 8446 §7.1)            */

    const x509_cert *roots;              /* trust store (NULL = no cert validation) */
    size_t           root_count;
    uint64_t         now;                /* Unix time for the validity check */
    tls_cert_chain   certs;              /* scratch: the parsed server chain        */
    uint8_t          leaf_spki[TLS_LEAF_SPKI_MAX];  /* leaf RSAPublicKey, kept for CV */
    size_t           leaf_spki_len;

    int       peer_authenticated;        /* true only after CertificateVerify (or a resumed Finished) passes */
    tls_error error;                     /* reason, when state == TLS_ST_ERROR        */
    int       cert_reason;               /* the specific TLS_CERT_* code, when error == TLS_ERR_CERT */

    /* Session resumption (Phase 15.7, RFC 8446 §2.2/§4.2.11/§4.6.1). */
    const tls_session_ticket *offered_resume;  /* set via tls_client_offer_psk(); NULL = full handshake only */
    uint64_t offer_now_ms;
    uint8_t  psk_early_secret[32];             /* valid only if offered_resume != NULL */
    uint8_t  binder_key[32];                   /* valid only if offered_resume != NULL */
    int      psk_accepted;                     /* set once the ServerHello is processed */
    uint8_t  resumption_master_secret[32];     /* set once CONNECTED, for a future ticket's PSK */
    int      has_resumption_secret;

    tls_trace_sink trace;                /* handshake trace sink (NULL = no tracing) */
    void          *trace_ctx;
} tls_client;

/* Initialize. `ephemeral_priv` and `client_random` make the engine fully
 * deterministic (supply real randomness in production). Trust is off by default. */
void tls_client_init(tls_client *c, const char *server_name,
                     const uint8_t ephemeral_priv[32],
                     const uint8_t client_random[32]);

/* Install a trust store so the Certificate message is validated at WAIT_CERT
 * (chain to a root + validity at `now` + hostname against the init server_name).
 * Without this, certificates are accepted as transcript bytes only. */
void tls_client_set_trust(tls_client *c, const x509_cert *roots, size_t root_count,
                          uint64_t now);

/* Install a handshake trace sink (NULL disables tracing). */
void tls_client_set_trace(tls_client *c, tls_trace_sink fn, void *ctx);

/* Offer a cached session ticket for resumption (Phase 15.7). Call after
 * tls_client_init() and before tls_client_start(); `resume` must outlive the
 * handshake. `now_ms` is used for the ticket's obfuscated_ticket_age. If the
 * server doesn't select this PSK (no pre_shared_key in its ServerHello), the
 * handshake transparently falls back to a full certificate-based one -- this
 * is an offer, not a requirement. Pass `resume = NULL` for a full handshake
 * only (the pre-15.7 behavior, unconditionally). */
void tls_client_offer_psk(tls_client *c, const tls_session_ticket *resume, uint64_t now_ms);

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
