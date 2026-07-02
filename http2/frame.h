/* HTTP/2 frame layer (RFC 7540 §4.1) — Phase 17.1.1; a generic incremental
 * frame reader — Phase 17.1.2.
 *
 * The frame header: 9 bytes of length/type/flags/stream_id shared by every
 * HTTP/2 frame type, plus the connection preface that precedes the very
 * first one, plus (17.1.2) h2_frame_reader -- a byte-stream-to-frame
 * reassembler, the same role tls_record_reader plays for TLS records: an
 * HTTP/2 frame boundary has no relationship whatsoever to a TLS record
 * boundary (or a raw socket read boundary), so a frame's header or payload
 * can arrive split across either. 17.1.1's own h2_handshake() hand-rolled
 * this reassembly inline with an ad-hoc "accumulate a partial header, skip
 * whatever payload isn't a frame type this call cares about" loop; 17.1.2
 * promotes that into a real, reusable, payload-preserving reader so a later
 * phase (HEADERS, streams) doesn't have to duplicate it. Pure byte<->struct,
 * no networking, no allocation — freestanding and host-testable, same
 * convention as crypto/tls/x509/compress. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define H2_FRAME_HEADER_LEN 9

/* Frame types actually named yet (RFC 7540 §11.2); more get added as later
 * phases need them (HEADERS payload semantics, DATA, etc.). */
#define H2_TYPE_DATA          0x0
#define H2_TYPE_HEADERS       0x1
#define H2_TYPE_PRIORITY      0x2
#define H2_TYPE_RST_STREAM    0x3
#define H2_TYPE_SETTINGS      0x4
#define H2_TYPE_PUSH_PROMISE  0x5
#define H2_TYPE_PING          0x6
#define H2_TYPE_GOAWAY        0x7
#define H2_TYPE_WINDOW_UPDATE 0x8
#define H2_TYPE_CONTINUATION  0x9

#define H2_FLAG_ACK        0x1   /* SETTINGS/PING: this frame acknowledges one the peer sent */
#define H2_FLAG_END_STREAM 0x1   /* DATA/HEADERS: no more frames follow for this stream (17.1.2).
                                  * Same bit value as H2_FLAG_ACK -- RFC 7540 §4.1 flags are scoped
                                  * per frame *type*, not global, so this is fine as long as callers
                                  * only ever test a flag against a frame of the type it applies to
                                  * (exactly how h2_is_settings_ack() already works). */
#define H2_FLAG_PADDED     0x8   /* DATA/HEADERS: payload begins with a 1-byte Pad Length (17.1.2) */

/* The connection preface (RFC 7540 §3.5): the literal first bytes an HTTP/2
 * client sends, before any frame at all -- both to let a misconfigured
 * HTTP/1.1-only server fail fast and recognizably, and (this codebase's
 * actual use) to give an HTTP/2-aware server an unambiguous "this really is
 * h2" signal even though ALPN already told it that during the TLS handshake. */
#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN 24

typedef struct {
    uint32_t length;      /* 24-bit payload length (0 .. 2^24-1) */
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;   /* 31-bit; the reserved top bit is always written/read as 0 */
} h2_frame_header;

/* Write a 9-byte frame header into `out`. Returns H2_FRAME_HEADER_LEN, or -1
 * if `cap` is too small or a field doesn't fit its wire width. */
int h2_write_frame_header(uint8_t *out, size_t cap, const h2_frame_header *h);

/* Parse a 9-byte frame header from `in`. Returns H2_FRAME_HEADER_LEN, or -1
 * if `len` is too small. Always succeeds otherwise -- every 9-byte pattern
 * is a structurally valid frame header (RFC 7540 imposes no header-level
 * constraints beyond the reserved bit, which is simply ignored on read, per
 * §4.1: "unused flags MUST be ignored on receipt"). */
int h2_parse_frame_header(const uint8_t *in, size_t len, h2_frame_header *out);

/* ------------------------------------------------------------------ */
/* Generic incremental frame reader (Phase 17.1.2)                    */
/* ------------------------------------------------------------------ */

/* RFC 7540 §6.5.2's default SETTINGS_MAX_FRAME_SIZE. Aurora never offers a
 * larger one (its own SETTINGS frame -- 17.1.1 -- is empty, i.e. every
 * default applies), so this is the ceiling every frame worth holding in
 * full will ever need -- a peer that sends a larger one is misbehaving,
 * not something this client needs to accommodate. */
#define H2_FRAME_PAYLOAD_MAX 16384

/* Buffers one frame (header + full payload) at a time, fed arbitrarily-
 * chunked plaintext bytes. Deliberately single-frame, not a queue: nothing
 * in this client needs more than one frame in flight before acting on it
 * (matching the whole file's fully-synchronous, no-concurrency design). */
typedef struct {
    uint8_t buf[H2_FRAME_HEADER_LEN + H2_FRAME_PAYLOAD_MAX];
    size_t  len;    /* bytes currently buffered (header, or header+payload-so-far) */
    size_t  need;   /* total bytes needed to complete what's buffered so far;
                     * H2_FRAME_HEADER_LEN until the header itself is complete,
                     * then header+declared-payload-length */
} h2_frame_reader;

void h2_frame_reader_init(h2_frame_reader *r);

/* Feed newly-arrived plaintext bytes (decrypted TLS app-data, or any other
 * byte source -- arbitrary chunking, no assumption about frame alignment).
 * Returns 0 normally. Returns -1 if the frame currently being assembled
 * declares a payload length larger than H2_FRAME_PAYLOAD_MAX (RFC 7540
 * §4.2's frame size error -- fatal here; Aurora has no larger
 * SETTINGS_MAX_FRAME_SIZE to have offered, so this can only mean a
 * misbehaving peer, not a negotiation Aurora itself failed to do). */
int h2_frame_reader_feed(h2_frame_reader *r, const uint8_t *data, size_t len);

/* If a complete frame (header + full payload) is now buffered, fills *out
 * with its header, sets *payload and *payload_len to its payload bytes (a view
 * into the reader's own internal buffer -- valid only until the next feed()
 * or next() call), consumes the frame from the reader, and returns 1.
 * Returns 0 if no complete frame is buffered yet (feed more first). One
 * feed() can complete more than one frame -- call next() in a loop until it
 * returns 0, the same shape tls_reader_next() already has for TLS records. */
int h2_frame_reader_next(h2_frame_reader *r, h2_frame_header *out,
                         const uint8_t **payload, size_t *payload_len);
