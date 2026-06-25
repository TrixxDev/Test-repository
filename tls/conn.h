/* TLS 1.3 record binding (RFC 8446 §5) — the layer between raw TLS records and
 * the handshake state machine. v1.
 *
 * Responsibilities (and nothing more):
 *   1. Plaintext-vs-encrypted gating. ClientHello and ServerHello travel as
 *      plaintext handshake records; everything after ServerHello is an encrypted
 *      application_data record (RFC 8446 §5.1). The conn decides which based on
 *      the FSM's key phase, NOT the record layer.
 *   2. Key switching at the two phase anchors. ServerHello -> handshake traffic
 *      keys; server Finished -> application traffic keys. Each switch installs a
 *      fresh record epoch, so its sequence number restarts at 0 (§5.3): TLS 1.3
 *      treats a key change as a new encryption epoch.
 *   3. Handshake reassembly. One record may coalesce several handshake messages
 *      (EncryptedExtensions|Certificate|CertificateVerify|Finished), or split one
 *      message across records. The conn buffers bytes and hands the FSM exactly
 *      one complete handshake message at a time.
 *
 * Dependency direction is one-way: conn -> { FSM, record layer } -> crypto. The
 * record layer never inspects handshake state, and the FSM never sees a record or
 * the network. As a direct consequence a record-layer (AEAD) failure is a
 * transport error that leaves the FSM untouched, whereas only a real protocol
 * violation drives the FSM to ERROR — the two are reported with distinct codes.
 *
 * Certificates are still not validated (v1): the FSM transcripts them blindly.
 * No networking here either — records in, records out, fully host-testable. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "client.h"
#include "record.h"

/* Reassembly buffer: room for handshake bytes left over from a previous record
 * plus one full record's plaintext. A handshake message (e.g. a large
 * certificate chain) larger than this is rejected rather than overflowing.
 *
 * Sizing (15.0.4 analysis): the single largest handshake message is Certificate.
 * With TLS_MAX_CHAIN=6 and RSA-4096 certs (~1.8 KiB each) a chain can reach
 * ~11 KiB, and recv_record may add one more full 16 KiB-plaintext record before
 * run_splitter consumes it, so the peak (~27 KiB) needs more than 1x 16 KiB. 2x
 * (32 KiB) covers it with margin; this is NOT over-provisioned -- 1x would reject
 * a deep RSA chain. Verify-only client, so no constant-time concern. */
#define TLS_CONN_HS_BUF (2 * TLS_RECORD_MAX_PLAINTEXT)

/* Return codes. >=0 from the byte-producing calls is a length; the codes below
 * are the negative errors. ERR_RECORD (malformed / AEAD failure) deliberately
 * leaves the FSM intact; ERR_PROTOCOL means the FSM rejected a message and is now
 * in TLS_ST_ERROR. */
#define TLS_CONN_OK            0
#define TLS_CONN_ERR_RECORD   -1   /* malformed record or AEAD auth failure (FSM intact) */
#define TLS_CONN_ERR_PROTOCOL -2   /* handshake/FSM rejected the message (FSM -> ERROR)  */
#define TLS_CONN_ERR_ALERT    -3   /* peer sent an alert record                          */
#define TLS_CONN_ERR_CAPACITY -4   /* output or reassembly buffer too small              */

typedef struct {
    tls_client fsm;                 /* the handshake state machine */

    tls_record_keys rx;             /* current read epoch  (own seq, reset per epoch) */
    tls_record_keys tx;             /* current write epoch (own seq, reset per epoch) */
    tls_key_phase   rx_phase;       /* epoch whose keys rx currently holds (EARLY = none) */
    tls_key_phase   tx_phase;

    uint8_t hs_buf[TLS_CONN_HS_BUF];   /* handshake reassembly (coalesce / fragment) */
    size_t  hs_len;
} tls_conn;

/* Initialize. `ephemeral_priv` and `client_random` make the whole connection
 * deterministic (supply real randomness in production). Starts in the EARLY
 * (plaintext) epoch; record keys are installed at the phase anchors. */
void tls_conn_init(tls_conn *c, const char *server_name,
                   const uint8_t ephemeral_priv[32],
                   const uint8_t client_random[32]);

/* Produce the initial flight: the ClientHello wrapped in a *plaintext* handshake
 * record, written to `out`. Returns the record length or a negative error. */
int tls_conn_start(tls_conn *c, uint8_t *out, size_t outcap);

/* Feed one complete TLS record (header + body) carrying part of the handshake.
 * Plaintext records (ServerHello) are taken as-is; encrypted records are opened
 * with the current rx epoch. The contained handshake message(s) drive the FSM,
 * and any message the FSM emits in response (the client Finished) is sealed with
 * the current tx epoch and written to `out` (its length in *out_len; 0 if none).
 * ChangeCipherSpec records are ignored (TLS 1.3 middlebox compatibility).
 * Returns TLS_CONN_OK or a negative error code. */
int tls_conn_recv_record(tls_conn *c, const uint8_t *record, size_t reclen,
                         uint8_t *out, size_t outcap, size_t *out_len);

/* Seal application data once CONNECTED: writes one application_data record to
 * `out`, returns its length or a negative error. */
int tls_conn_send_app(tls_conn *c, const uint8_t *data, size_t len,
                      uint8_t *out, size_t outcap);

/* Open one application_data record once CONNECTED: writes the plaintext to `out`
 * (length in *out_len). Post-handshake handshake messages (NewSessionTicket) are
 * accepted and ignored (*out_len = 0). Returns TLS_CONN_OK or a negative error. */
int tls_conn_recv_app(tls_conn *c, const uint8_t *record, size_t reclen,
                      uint8_t *out, size_t outcap, size_t *out_len);

static inline int tls_conn_connected(const tls_conn *c)
{
    return c->fsm.state == TLS_ST_CONNECTED;
}

/* Install a handshake trace sink on the underlying FSM (NULL disables it). */
static inline void tls_conn_set_trace(tls_conn *c, tls_trace_sink fn, void *ctx)
{
    tls_client_set_trace(&c->fsm, fn, ctx);
}
