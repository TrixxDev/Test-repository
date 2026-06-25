/* TLS record framing over a byte stream (RFC 8446 §5.1) — the bottom seam of
 * TLS-over-sockets. v1.
 *
 * Source-agnostic by construction: you feed it bytes from *anywhere* (a socket,
 * a recorded trace file, a fuzzer) and pull complete TLS records out. It knows
 * nothing about sockets, content types, or the handshake — only the 5-byte
 * record header (type | legacy_version | uint16 length) and the wire length
 * limit. A complete record is handed up to tls_conn_recv_record() unchanged.
 *
 * Contract: a record returned by tls_reader_next() points into the reader's own
 * buffer and is valid until the next tls_reader_feed() (which may compact). Drain
 * with next() until it returns 0 before feeding more, and the buffer stays small.
 * Freestanding: only <stdint.h>/<stddef.h>. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "record.h"     /* TLS_RECORD_HEADER_LEN, TLS_RECORD_MAX_PLAINTEXT */

/* Max TLSCiphertext.length on the wire: plaintext (2^14) + up to 256 of inner
 * type + padding + AEAD expansion (RFC 8446 §5.2). A larger length is malformed. */
#define TLS_RECORD_MAX_BODY  (TLS_RECORD_MAX_PLAINTEXT + 256)
#define TLS_RECORD_MAX_WIRE  (TLS_RECORD_HEADER_LEN + TLS_RECORD_MAX_BODY)

/* Buffer = one max record plus a generous feed chunk, so a caller that drains
 * after each feed never overflows.
 *
 * Sizing (15.0.4 analysis): feed() compacts then appends, and callers drain every
 * complete record before the next read, so the peak is (one partial wire record,
 * < TLS_RECORD_MAX_WIRE) + (one feed chunk). The floor is hard -- a compliant
 * server may send a full 16 KiB-plaintext record, which must fit whole before it
 * can be framed. The +16384 margin admits feed chunks up to a full record, which
 * keeps the contract general (current callers feed <= 4 KiB; this leaves headroom
 * rather than constraining the read size). Not over-provisioned for the RFC max. */
#define TLS_READER_BUF       (TLS_RECORD_MAX_WIRE + 16384)

typedef struct {
    uint8_t buf[TLS_READER_BUF];
    size_t  start;      /* first unconsumed byte */
    size_t  len;        /* total valid bytes */
    int     error;      /* sticky: a malformed record was seen */
} tls_record_reader;

void tls_reader_init(tls_record_reader *r);

/* Append `len` bytes from any source. Returns 0, or -1 if they do not fit (the
 * caller must drain with next() between feeds). */
int  tls_reader_feed(tls_record_reader *r, const uint8_t *data, size_t len);

/* Pull the next complete record. Returns 1 and sets rec and reclen (valid until
 * the next feed), 0 if more bytes are needed, or -1 if the framed length exceeds
 * the wire limit (malformed; sticky). */
int  tls_reader_next(tls_record_reader *r, const uint8_t **rec, size_t *reclen);

/* Bytes buffered but not yet a complete record. A driver uses this at EOF: bytes
 * pending == a truncated stream (distinct from a clean record boundary). */
static inline size_t tls_reader_pending(const tls_record_reader *r) { return r->len - r->start; }
