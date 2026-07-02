/* HTTP/2 frame layer (RFC 7540 §4.1) — Phase 17.1.1.
 *
 * Just the frame header: 9 bytes of length/type/flags/stream_id shared by
 * every HTTP/2 frame type, plus the connection preface that precedes the
 * very first one. No frame *payload* semantics live here yet (HEADERS/DATA
 * are later phases) — this is deliberately the smallest reusable unit,
 * mirroring how compress/crc32.c was one primitive before compress/inflate.c
 * needed it. Pure byte<->struct, no networking, no allocation — freestanding
 * and host-testable, same convention as crypto/tls/x509/compress. */
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

#define H2_FLAG_ACK 0x1   /* SETTINGS/PING: this frame acknowledges one the peer sent */

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
