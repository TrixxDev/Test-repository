/* TLS 1.3 handshake driver — the top seam that binds a byte transport to the
 * handshake engine (RFC 8446). v1.
 *
 *      transport (socket)  ->  tls_record_reader  ->  tls_conn  ->  CONNECTED
 *
 * It owns the control loop and nothing else: send the ClientHello, then pull
 * complete records out of the reader, feed each to tls_conn, send back anything
 * tls_conn emits (the client Finished), and stop the instant the FSM reaches
 * CONNECTED. All the protocol logic already lives below it (tls_conn does record
 * binding / epoch switching / message reassembly; tls_record_reader does framing).
 *
 * Transport-agnostic by construction: it talks to the network only through the
 * read/write callbacks in tls_transport, so the very same driver runs over a
 * kernel socket fd, over a recorded trace, or over an adversarial host-test mock
 * that delivers the server flight one byte at a time. That is the whole point —
 * the record-stream handling (fragmented records, several records per read, a
 * message split across records) is then provable deterministically off the wire.
 *
 * Partial writes are assumed, never ignored: every outbound flight goes through
 * send_all(), which loops until all bytes are written, so the driver is correct
 * even if write() reports a short count. Freestanding: only <stdint.h>/<stddef.h>
 * plus the tls/ headers. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "conn.h"
#include "record_reader.h"

/* The only thing the driver knows about the network. read: >0 = bytes read,
 * 0 = clean EOF (peer closed), <0 = transport error. write: returns bytes
 * written (MAY be < len — a partial write), 0 = no progress, <0 = error; the
 * driver loops over it so callers never assume a full write. */
typedef struct {
    int (*read)(void *ctx, uint8_t *buf, size_t cap);
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    void *ctx;
} tls_transport;

typedef enum {
    TLS_DRIVE_OK        =  0,   /* reached CONNECTED (client Finished sent) */
    TLS_DRIVE_EOF       = -1,   /* transport closed before CONNECTED */
    TLS_DRIVE_READ_ERR  = -2,   /* transport read() returned an error */
    TLS_DRIVE_WRITE_ERR = -3,   /* transport write() could not make progress */
    TLS_DRIVE_PROTOCOL  = -4,   /* tls_conn rejected a record (see conn->fsm.error / trace) */
    TLS_DRIVE_OVERFLOW  = -5,   /* reader stream buffer overflowed */
    TLS_DRIVE_MALFORMED = -6,   /* a framed record length exceeded the wire limit */
} tls_drive_result;

/* Drive the handshake to CONNECTED. `conn` must be tls_conn_init'd (with trust
 * and trace installed as desired); `reader` must be tls_reader_init'd. `scratch`
 * is working space for the outbound ClientHello/Finished records and for incoming
 * reads — size it >= one max-size outbound record (>= ~1100 is plenty). Returns
 * TLS_DRIVE_OK at CONNECTED, or a negative tls_drive_result. */
int tls_driver_handshake(tls_conn *conn, tls_record_reader *reader,
                         const tls_transport *t, uint8_t *scratch, size_t scratch_len);
