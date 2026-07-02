/* Host-side HTTP/2 frame layer test (http2/: RFC 7540 §4.1 frame header,
 * §6.5 SETTINGS, §6.1 DATA, and the generic incremental frame reader).
 * No networking -- pure byte<->struct, exercised entirely on the host.
 * Build/run: `make h2-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "frame.h"
#include "settings.h"
#include "data.h"
#include "hpack.h"
#include "headers.h"
#include "huffman.h"
#include "hpack_table.h"
#include "hpack_decode.h"

static int failures;

static void check_field(const char *name, const hpack_header_field *f, const char *want_name, const char *want_value)
{
    size_t wn = strlen(want_name), wv = strlen(want_value);
    int ok = f->name_len == wn && memcmp(f->name, want_name, wn) == 0 &&
             f->value_len == wv && memcmp(f->value, want_value, wv) == 0;
    if (ok) {
        printf("  PASS  %s\n", name);
    } else {
        char got_name[128], got_value[256];
        int gn = f->name_len < sizeof got_name - 1 ? (int)f->name_len : (int)sizeof got_name - 1;
        int gv = f->value_len < sizeof got_value - 1 ? (int)f->value_len : (int)sizeof got_value - 1;
        memcpy(got_name, f->name, gn); got_name[gn] = 0;
        memcpy(got_value, f->value, gv); got_value[gv] = 0;
        printf("  FAIL  %s\n        got  %s: %s\n        want %s: %s\n", name, got_name, got_value, want_name, want_value);
        failures++;
    }
}

static int fromhex(const char *hex, uint8_t *out)
{
    int n = 0;
    for (int i = 0; hex[i] && hex[i + 1]; i += 2) {
        int hi = hex[i] <= '9' ? hex[i] - '0' : hex[i] - 'a' + 10;
        int lo = hex[i + 1] <= '9' ? hex[i + 1] - '0' : hex[i + 1] - 'a' + 10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void check_int(const char *name, int got, int want)
{
    if (got == want) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %d\n        want %d\n", name, got, want);
        failures++;
    }
}

static void tohex(const uint8_t *b, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}

static void check_hex(const char *name, const uint8_t *got, int n, const char *want)
{
    char hex[64];
    tohex(got, n, hex);
    if (strcmp(hex, want) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want);
        failures++;
    }
}

int main(void)
{
    printf("HTTP/2 frame header (RFC 7540 SS4.1):\n");
    {
        h2_frame_header h = { 0, 0, 0, 0 };
        uint8_t buf[H2_FRAME_HEADER_LEN];
        check_int("write returns the fixed 9-byte length", h2_write_frame_header(buf, sizeof buf, &h), H2_FRAME_HEADER_LEN);

        /* known encoding: length=100 (0x000064), type=SETTINGS(4), flags=ACK(1), stream_id=0 */
        h2_frame_header known = { 100, H2_TYPE_SETTINGS, H2_FLAG_ACK, 0 };
        h2_write_frame_header(buf, sizeof buf, &known);
        check_hex("known encoding matches byte-for-byte", buf, H2_FRAME_HEADER_LEN, "000064040100000000");

        /* round-trip: write then parse recovers every field exactly, incl. boundary values */
        h2_frame_header cases[] = {
            { 0,        H2_TYPE_DATA,          0,               0 },
            { 0xFFFFFF, H2_TYPE_HEADERS,        0xFF,            0x7FFFFFFFu },
            { 6,        H2_TYPE_SETTINGS,       0,               0 },
            { 16384,    H2_TYPE_WINDOW_UPDATE,  0,               1 },
        };
        for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            uint8_t b[H2_FRAME_HEADER_LEN];
            h2_frame_header out;
            int wn = h2_write_frame_header(b, sizeof b, &cases[i]);
            int pn = wn > 0 ? h2_parse_frame_header(b, (size_t)wn, &out) : -1;
            int ok = wn == H2_FRAME_HEADER_LEN && pn == H2_FRAME_HEADER_LEN &&
                     out.length == cases[i].length && out.type == cases[i].type &&
                     out.flags == cases[i].flags && out.stream_id == cases[i].stream_id;
            char name[64]; snprintf(name, sizeof name, "round-trip case %u", i);
            check_int(name, ok, 1);
        }

        /* the reserved top bit of stream_id is always written/read as 0 -- a
         * peer that sets it (a real, if rare, wire possibility per SS4.1's
         * "MUST be ignored on receipt") must not corrupt the 31-bit value. */
        {
            uint8_t b[H2_FRAME_HEADER_LEN] = { 0, 0, 0, 0, 0, 0x80, 0, 0, 1 };  /* reserved bit set, stream_id=1 */
            h2_frame_header out;
            h2_parse_frame_header(b, sizeof b, &out);
            check_int("reserved bit on the wire doesn't corrupt stream_id", (int)out.stream_id, 1);
        }

        /* capacity / range rejection */
        check_int("write rejects an undersized buffer", h2_write_frame_header(buf, 8, &h), -1);
        check_int("parse rejects an undersized buffer", h2_parse_frame_header(buf, 8, &h), -1);
        h2_frame_header toobig_len = { 0x1000000, 0, 0, 0 };   /* one past the 24-bit max */
        check_int("write rejects a length that doesn't fit 24 bits", h2_write_frame_header(buf, sizeof buf, &toobig_len), -1);
        h2_frame_header toobig_sid = { 0, 0, 0, 0x80000000u };  /* one past the 31-bit max */
        check_int("write rejects a stream_id that doesn't fit 31 bits", h2_write_frame_header(buf, sizeof buf, &toobig_sid), -1);
    }

    printf("HTTP/2 SETTINGS (RFC 7540 SS6.5):\n");
    {
        uint8_t buf[H2_FRAME_HEADER_LEN];
        check_int("empty SETTINGS builds", h2_build_settings_empty(buf, sizeof buf), H2_FRAME_HEADER_LEN);
        check_hex("empty SETTINGS: length=0, type=4, flags=0, stream=0", buf, H2_FRAME_HEADER_LEN, "000000040000000000");

        check_int("SETTINGS ACK builds", h2_build_settings_ack(buf, sizeof buf), H2_FRAME_HEADER_LEN);
        check_hex("SETTINGS ACK: length=0, type=4, flags=ACK, stream=0", buf, H2_FRAME_HEADER_LEN, "000000040100000000");

        h2_frame_header parsed;
        h2_parse_frame_header(buf, sizeof buf, &parsed);
        check_int("h2_is_settings_ack() recognizes a real SETTINGS ACK", h2_is_settings_ack(&parsed), 1);

        h2_frame_header real_settings = { 12, H2_TYPE_SETTINGS, 0, 0 };
        check_int("h2_is_settings_ack() rejects a non-ACK SETTINGS frame", h2_is_settings_ack(&real_settings), 0);

        /* the ACK flag bit (0x1) means something different on other frame
         * types (e.g. DATA's END_STREAM) -- h2_is_settings_ack() must key
         * off the type, not just the flag bit. */
        h2_frame_header data_end_stream = { 0, H2_TYPE_DATA, H2_FLAG_ACK, 1 };
        check_int("h2_is_settings_ack() ignores the bit on a non-SETTINGS frame", h2_is_settings_ack(&data_end_stream), 0);

        check_int("SETTINGS payload length 0 is valid (empty)", h2_settings_payload_valid(0), 1);
        check_int("SETTINGS payload length 6 is valid (one parameter)", h2_settings_payload_valid(6), 1);
        check_int("SETTINGS payload length 18 is valid (three parameters)", h2_settings_payload_valid(18), 1);
        check_int("SETTINGS payload length 5 is invalid (not a multiple of 6)", h2_settings_payload_valid(5), 0);
        check_int("SETTINGS payload length 7 is invalid (not a multiple of 6)", h2_settings_payload_valid(7), 0);
    }

    printf("HTTP/2 generic frame reader (Phase 17.1.2):\n");
    {
        /* 1. a whole empty-payload frame (SETTINGS ACK-shaped) fed in one call */
        {
            h2_frame_reader r; h2_frame_reader_init(&r);
            uint8_t f[H2_FRAME_HEADER_LEN];
            h2_build_settings_ack(f, sizeof f);
            int fed = h2_frame_reader_feed(&r, f, sizeof f);
            check_int("whole empty frame: feed() consumes all 9 bytes", fed, H2_FRAME_HEADER_LEN);
            h2_frame_header out; const uint8_t *payload; size_t payload_len;
            int got = h2_frame_reader_next(&r, &out, &payload, &payload_len);
            check_int("whole empty frame: next() reports it complete", got, 1);
            check_int("whole empty frame: type is SETTINGS", out.type, H2_TYPE_SETTINGS);
            check_int("whole empty frame: ACK flag set", (out.flags & H2_FLAG_ACK) != 0, 1);
            check_int("whole empty frame: payload_len is 0", (int)payload_len, 0);
            check_int("whole empty frame: next() has nothing more", h2_frame_reader_next(&r, &out, &payload, &payload_len), 0);
        }

        /* 2. the exact same frame, fed one byte at a time -- a header (or
         * payload) split across an arbitrary number of separate reads must
         * reassemble identically to the whole-frame case above. */
        {
            h2_frame_reader r; h2_frame_reader_init(&r);
            uint8_t f[H2_FRAME_HEADER_LEN];
            h2_build_settings_empty(f, sizeof f);
            int all_ready_early = 0;
            for (int i = 0; i < H2_FRAME_HEADER_LEN; i++) {
                h2_frame_header dummy; const uint8_t *p; size_t pl;
                if (i < H2_FRAME_HEADER_LEN - 1 && h2_frame_reader_next(&r, &dummy, &p, &pl) == 1) all_ready_early = 1;
                h2_frame_reader_feed(&r, f + i, 1);
            }
            check_int("byte-at-a-time: not reported complete before the last byte arrived", all_ready_early, 0);
            h2_frame_header out; const uint8_t *payload; size_t payload_len;
            check_int("byte-at-a-time: complete exactly after the last byte", h2_frame_reader_next(&r, &out, &payload, &payload_len), 1);
            check_int("byte-at-a-time: type is SETTINGS (non-ACK)", out.type, H2_TYPE_SETTINGS);
            check_int("byte-at-a-time: ACK flag clear", (out.flags & H2_FLAG_ACK) != 0, 0);
        }

        /* 3. a frame with a real (nonzero) payload, split at an arbitrary
         * point that falls INSIDE the payload, not just the header. */
        {
            h2_frame_reader r; h2_frame_reader_init(&r);
            uint8_t payload_in[12] = { 0,1,2,3,4,5,6,7,8,9,10,11 };
            h2_frame_header h = { sizeof payload_in, H2_TYPE_DATA, 0, 7 };
            uint8_t f[H2_FRAME_HEADER_LEN + sizeof payload_in];
            h2_write_frame_header(f, sizeof f, &h);
            memcpy(f + H2_FRAME_HEADER_LEN, payload_in, sizeof payload_in);
            /* split at byte 13: 4 bytes into the payload */
            int fed1 = h2_frame_reader_feed(&r, f, 13);
            check_int("payload split: first feed consumes exactly what was offered", fed1, 13);
            h2_frame_header dummy; const uint8_t *p; size_t pl;
            check_int("payload split: not complete yet", h2_frame_reader_next(&r, &dummy, &p, &pl), 0);
            int fed2 = h2_frame_reader_feed(&r, f + 13, sizeof f - 13);
            check_int("payload split: second feed consumes the rest", fed2, (int)(sizeof f - 13));
            h2_frame_header out; const uint8_t *payload; size_t payload_len;
            check_int("payload split: now complete", h2_frame_reader_next(&r, &out, &payload, &payload_len), 1);
            check_int("payload split: stream_id preserved", (int)out.stream_id, 7);
            check_int("payload split: payload_len matches", (int)payload_len, (int)sizeof payload_in);
            check_int("payload split: payload bytes match", memcmp(payload, payload_in, sizeof payload_in) == 0, 1);
        }

        /* 4. two complete frames delivered in ONE feed() call -- next() must
         * drain both, in order, without needing another feed() in between. */
        {
            h2_frame_reader r; h2_frame_reader_init(&r);
            uint8_t f1[H2_FRAME_HEADER_LEN], f2[H2_FRAME_HEADER_LEN];
            h2_build_settings_empty(f1, sizeof f1);
            h2_build_settings_ack(f2, sizeof f2);
            uint8_t both[2 * H2_FRAME_HEADER_LEN];
            memcpy(both, f1, H2_FRAME_HEADER_LEN);
            memcpy(both + H2_FRAME_HEADER_LEN, f2, H2_FRAME_HEADER_LEN);
            int fed = h2_frame_reader_feed(&r, both, sizeof both);
            check_int("two frames in one feed: first feed() call takes only the first frame's bytes",
                      fed, H2_FRAME_HEADER_LEN);
            h2_frame_header out1; const uint8_t *p1; size_t pl1;
            check_int("two frames in one feed: first frame ready", h2_frame_reader_next(&r, &out1, &p1, &pl1), 1);
            check_int("two frames in one feed: first frame is the non-ACK one", (out1.flags & H2_FLAG_ACK) != 0, 0);
            int fed2 = h2_frame_reader_feed(&r, both + fed, sizeof both - (size_t)fed);
            check_int("two frames in one feed: second feed() call takes the second frame's bytes",
                      fed2, H2_FRAME_HEADER_LEN);
            h2_frame_header out2; const uint8_t *p2; size_t pl2;
            check_int("two frames in one feed: second frame ready", h2_frame_reader_next(&r, &out2, &p2, &pl2), 1);
            check_int("two frames in one feed: second frame is the ACK", (out2.flags & H2_FLAG_ACK) != 0, 1);
        }

        /* 5. a frame declaring a payload larger than H2_FRAME_PAYLOAD_MAX is
         * a frame size error (RFC 7540 SS4.2) -- rejected, not buffered. */
        {
            h2_frame_reader r; h2_frame_reader_init(&r);
            h2_frame_header h = { H2_FRAME_PAYLOAD_MAX + 1, H2_TYPE_DATA, 0, 1 };
            uint8_t hdr[H2_FRAME_HEADER_LEN];
            h2_write_frame_header(hdr, sizeof hdr, &h);
            check_int("oversized frame declaration is rejected", h2_frame_reader_feed(&r, hdr, sizeof hdr), -1);
        }
    }

    printf("HTTP/2 DATA frame (RFC 7540 SS6.1, Phase 17.1.2):\n");
    {
        /* unpadded: the whole payload is data */
        {
            uint8_t payload[5] = { 'h','e','l','l','o' };
            const uint8_t *data; size_t data_len;
            check_int("unpadded DATA parses", h2_data_parse(payload, sizeof payload, 0, &data, &data_len), 0);
            check_int("unpadded DATA: data_len is the whole payload", (int)data_len, (int)sizeof payload);
            check_int("unpadded DATA: data points at the payload itself", data == payload, 1);
        }

        /* padded: [padlen=3][data="hi"][3 bytes of padding] */
        {
            uint8_t payload[] = { 3, 'h', 'i', 0, 0, 0 };
            const uint8_t *data; size_t data_len;
            check_int("padded DATA parses", h2_data_parse(payload, sizeof payload, H2_FLAG_PADDED, &data, &data_len), 0);
            check_int("padded DATA: data_len excludes the pad-length byte and padding", (int)data_len, 2);
            check_int("padded DATA: data starts right after the pad-length byte", data == payload + 1, 1);
            check_int("padded DATA: data bytes match", memcmp(data, "hi", 2) == 0, 1);
        }

        /* padding >= whole payload -- RFC 7540 SS6.1 connection error */
        {
            uint8_t payload[] = { 5, 'h', 'i' };   /* padlen=5 but only 2 bytes follow */
            const uint8_t *data; size_t data_len;
            check_int("DATA with padding >= payload is rejected",
                      h2_data_parse(payload, sizeof payload, H2_FLAG_PADDED, &data, &data_len), -1);
        }

        /* PADDED flag but zero-length payload -- no room for the pad-length byte itself */
        {
            const uint8_t *data; size_t data_len;
            check_int("PADDED DATA with an empty payload is rejected",
                      h2_data_parse((const uint8_t*)"", 0, H2_FLAG_PADDED, &data, &data_len), -1);
        }

        /* build: header + payload round-trips, END_STREAM flag set/clear correctly */
        {
            uint8_t out[64];
            const uint8_t body[] = "some body bytes";
            int n = h2_data_build(out, sizeof out, 3, body, sizeof body - 1, 1 /* end_stream */);
            check_int("DATA build succeeds", n > 0, 1);
            h2_frame_header h;
            h2_parse_frame_header(out, (size_t)n, &h);
            check_int("DATA build: type is DATA", h.type, H2_TYPE_DATA);
            check_int("DATA build: stream_id preserved", (int)h.stream_id, 3);
            check_int("DATA build: length matches the body", (int)h.length, (int)(sizeof body - 1));
            check_int("DATA build: END_STREAM flag set", (h.flags & H2_FLAG_END_STREAM) != 0, 1);
            check_int("DATA build: payload bytes match", memcmp(out + H2_FRAME_HEADER_LEN, body, sizeof body - 1) == 0, 1);

            int n2 = h2_data_build(out, sizeof out, 3, body, sizeof body - 1, 0 /* not end_stream */);
            h2_frame_header h2out;
            h2_parse_frame_header(out, (size_t)n2, &h2out);
            check_int("DATA build: END_STREAM flag clear when not requested", (h2out.flags & H2_FLAG_END_STREAM) != 0, 0);
        }

        /* capacity rejection -- an undersized output buffer must fail loudly, not truncate */
        {
            uint8_t small[H2_FRAME_HEADER_LEN + 2];
            const uint8_t body[] = "way too long for this buffer";
            check_int("DATA build rejects an undersized buffer",
                      h2_data_build(small, sizeof small, 1, body, sizeof body - 1, 0), -1);
        }
    }

    printf("HPACK integer/string encoding (RFC 7541 SS5.1/SS5.2, Phase 17.1.3):\n");
    {
        uint8_t buf[16]; size_t pos;

        /* RFC 7541 SS5.1's own worked example: 1337 with a 5-bit prefix. */
        pos = 0;
        check_int("hpack_put_int builds", hpack_put_int(buf, sizeof buf, &pos, 5, 0x00, 1337), 0);
        check_hex("1337 with a 5-bit prefix matches RFC 7541 SS5.1's own example", buf, (int)pos, "1f9a0a");

        /* a value that fits directly in the prefix needs no continuation byte */
        pos = 0;
        hpack_put_int(buf, sizeof buf, &pos, 5, 0x00, 10);
        check_hex("10 with a 5-bit prefix (fits directly, no continuation)", buf, (int)pos, "0a");

        /* string literal: length prefix (Huffman bit clear) + raw bytes */
        pos = 0;
        hpack_put_string(buf, sizeof buf, &pos, "hi", 2);
        check_hex("string \"hi\": length=2, Huffman bit clear, raw bytes", buf, (int)pos, "026869");

        /* indexed header field (RFC 7541 SS6.1): :method GET is index 2, :scheme https is index 7 */
        pos = 0;
        hpack_put_indexed(buf, sizeof buf, &pos, HPACK_IDX_METHOD_GET);
        check_hex("indexed :method GET (index 2)", buf, (int)pos, "82");
        pos = 0;
        hpack_put_indexed(buf, sizeof buf, &pos, HPACK_IDX_SCHEME_HTTPS);
        check_hex("indexed :scheme https (index 7)", buf, (int)pos, "87");

        /* literal with an indexed name (RFC 7541 SS6.2.2): :authority (index 1) = "a.b"
         * -- 01 (name_index=1, fits the 4-bit prefix directly) + 03 (length=3,
         * Huffman bit clear) + 61 2e 62 ('a' '.' 'b'). */
        pos = 0;
        hpack_put_literal_indexed_name(buf, sizeof buf, &pos, HPACK_IDX_AUTHORITY, "a.b", 3);
        check_hex("literal :authority = \"a.b\" (indexed name, literal value)", buf, (int)pos, "0103612e62");

        /* an index that doesn't fit the 4-bit prefix (max 15) needs a
         * continuation byte -- user-agent is index 58: first byte =
         * flag|15 = 0x0f, then (58-15)=43 as a single continuation byte
         * (43 < 128, so no further continuation needed). */
        pos = 0;
        hpack_put_int(buf, sizeof buf, &pos, 4, 0x00, HPACK_IDX_USER_AGENT);
        check_hex("index 58 (user-agent) with a 4-bit prefix needs a continuation byte", buf, (int)pos, "0f2b");
    }

    printf("HTTP/2 HEADERS frame, HPACK static table only (Phase 17.1.3):\n");
    {
        /* Every expected hex string below was hand-derived byte-by-byte
         * against RFC 7541's own encoding rules (see the derivation in the
         * commit/docs writeup) -- not copied from any external tool. */
        uint8_t out[256];

        /* GET / to www.example.com, no user-agent -- both :method and :path
         * are exactly the static table's own values, so everything except
         * :authority is a single indexed byte. */
        {
            int n = h2_build_headers(out, sizeof out, 1,
                                     "GET", 3, "www.example.com", 15,
                                     "/", 1, 0, 0);
            check_int("GET / builds", n > 0, 1);
            h2_frame_header h; h2_parse_frame_header(out, (size_t)n, &h);
            check_int("GET /: frame type is HEADERS", h.type, H2_TYPE_HEADERS);
            check_int("GET /: END_HEADERS set", (h.flags & H2_FLAG_END_HEADERS) != 0, 1);
            check_int("GET /: END_STREAM set (no request body over h2 yet)", (h.flags & H2_FLAG_END_STREAM) != 0, 1);
            check_int("GET /: stream_id preserved", (int)h.stream_id, 1);
            check_hex("GET / payload matches the hand-derived HPACK bytes",
                      out + H2_FRAME_HEADER_LEN, (int)h.length,
                      "8287010f7777772e6578616d706c652e636f6d84");
        }

        /* GET /page1 to 10.0.2.2, with a user-agent -- exercises a literal
         * :path (not "/") and the multi-byte user-agent index (58) together. */
        {
            const char *ua = "Aurora-httpsget/0.3";
            int n = h2_build_headers(out, sizeof out, 3,
                                     "GET", 3, "10.0.2.2", 8, "/page1", 6, ua, 19);
            check_int("GET /page1 + user-agent builds", n > 0, 1);
            h2_frame_header h; h2_parse_frame_header(out, (size_t)n, &h);
            check_int("GET /page1: stream_id preserved (3)", (int)h.stream_id, 3);
            check_hex("GET /page1 + user-agent payload matches the hand-derived HPACK bytes",
                      out + H2_FRAME_HEADER_LEN, (int)h.length,
                      "8287010831302e302e322e3204062f70616765310f2b134175726f72612d68747470736765742f302e33");
        }

        /* POST /submit -- :method POST is also a static-table indexed value (index 3). */
        {
            int n = h2_build_headers(out, sizeof out, 1,
                                     "POST", 4, "example.org", 11, "/submit", 7, 0, 0);
            check_int("POST /submit builds", n > 0, 1);
            h2_frame_header h; h2_parse_frame_header(out, (size_t)n, &h);
            check_hex("POST /submit payload matches the hand-derived HPACK bytes",
                      out + H2_FRAME_HEADER_LEN, (int)h.length,
                      "8387010b6578616d706c652e6f726704072f7375626d6974");
        }

        /* PUT /item -- :method PUT has no static-table value, so it's the
         * one case that exercises a literal :method (indexed-name-only,
         * using GET's index 2 for the name, literal value "PUT"). */
        {
            int n = h2_build_headers(out, sizeof out, 1,
                                     "PUT", 3, "example.org", 11, "/item", 5, 0, 0);
            check_int("PUT /item builds", n > 0, 1);
            h2_frame_header h; h2_parse_frame_header(out, (size_t)n, &h);
            check_hex("PUT /item payload matches the hand-derived HPACK bytes",
                      out + H2_FRAME_HEADER_LEN, (int)h.length,
                      "020350555487010b6578616d706c652e6f726704052f6974656d");
        }

        /* capacity rejection -- an undersized output buffer must fail loudly */
        {
            uint8_t small[10];
            int n = h2_build_headers(small, sizeof small, 1,
                                     "GET", 3, "www.example.com", 15, "/", 1, 0, 0);
            check_int("HEADERS build rejects an undersized buffer", n, -1);
        }
    }

    printf("HPACK Huffman decoding (RFC 7541 Appendix B / Appendix C.4, Phase 17.2.1):\n");
    {
        /* The 257-entry code table was mechanically extracted from the RFC's
         * own published text (not hand-transcribed) -- see huffman.h and
         * docs/SECURITY.md, Step 17.2.1, for the methodology. The two
         * vectors below are the RFC's own worked Huffman examples, not
         * independently invented -- RFC 7541 SS C.4.1 and SS C.4.2. */
        uint8_t in[64], out[64]; int inlen; size_t outlen;

        inlen = fromhex("f1e3c2e5f23a6ba0ab90f4ff", in);
        check_int("SS C.4.1 vector decodes", hpack_huffman_decode(in, (size_t)inlen, out, sizeof out, &outlen), 0);
        check_int("SS C.4.1 vector: decoded length is 15", (int)outlen, 15);
        check_int("SS C.4.1 vector: decodes to \"www.example.com\"", memcmp(out, "www.example.com", 15) == 0, 1);

        inlen = fromhex("a8eb10649cbf", in);
        check_int("SS C.4.2 vector decodes", hpack_huffman_decode(in, (size_t)inlen, out, sizeof out, &outlen), 0);
        check_int("SS C.4.2 vector: decoded length is 8", (int)outlen, 8);
        check_int("SS C.4.2 vector: decodes to \"no-cache\"", memcmp(out, "no-cache", 8) == 0, 1);

        /* empty input decodes to an empty string, not an error */
        outlen = 999;
        check_int("empty input decodes", hpack_huffman_decode(in, 0, out, sizeof out, &outlen), 0);
        check_int("empty input: decoded length is 0", (int)outlen, 0);

        /* a single 0x00 byte: the first 5 bits are symbol '0' (code 0x00,
         * len 5), leaving 3 leftover bits (000) that must be padding -- but
         * valid padding is always all 1s (a prefix of EOS's own 30-bit
         * all-1s code), so this must be rejected, not silently accepted. */
        {
            uint8_t one[1] = { 0x00 };
            check_int("a single zero byte has invalid (non-all-1s) padding and is rejected",
                      hpack_huffman_decode(one, 1, out, sizeof out, &outlen), -1);
        }

        /* a run of 1-bits longer than any real symbol's code (max 28 bits)
         * and past even EOS's own 30 bits can only mean corrupt/malicious
         * input -- EOS itself must never be a decode target (RFC 7541
         * SS5.2: "the string literal itself is compressed using... EOS...
         * as a padding" but "the encoder MUST NOT generate...EOS"). */
        {
            uint8_t allones[4] = { 0xff, 0xff, 0xff, 0xff };
            check_int("a run of 1-bits longer than any valid code is rejected",
                      hpack_huffman_decode(allones, 4, out, sizeof out, &outlen), -1);
        }

        /* output capacity rejection -- decoding "www.example.com" (15
         * bytes) into a 5-byte buffer must fail loudly, not truncate. */
        {
            uint8_t small[5];
            inlen = fromhex("f1e3c2e5f23a6ba0ab90f4ff", in);
            check_int("Huffman decode rejects an undersized output buffer",
                      hpack_huffman_decode(in, (size_t)inlen, small, sizeof small, &outlen), -1);
        }
    }

    printf("HPACK dynamic table + full header block decode (RFC 7541 SS2.3.2/SS4/SS6, Phase 17.2.2):\n");
    {
        /* Isolated representation examples, RFC 7541 SS C.2.1-C.2.4. */
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[64]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[128]; size_t scratch_used;

            inlen = fromhex("400a637573746f6d2d6b65790d637573746f6d2d686561646572", in);
            check_int("C.2.1 (literal with incremental indexing) decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_field("C.2.1: custom-key: custom-header", &out[0], "custom-key", "custom-header");
            check_int("C.2.1: added to the dynamic table (1 entry)", t.count, 1);
            check_int("C.2.1: dynamic table size is 55 (10+13+32)", (int)t.size, 55);
        }
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[64]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[128]; size_t scratch_used;

            inlen = fromhex("040c2f73616d706c652f70617468", in);
            check_int("C.2.2 (literal without indexing, indexed name) decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_field("C.2.2: :path: /sample/path", &out[0], ":path", "/sample/path");
            check_int("C.2.2: dynamic table untouched (still empty)", t.count, 0);
        }
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[64]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[128]; size_t scratch_used;

            inlen = fromhex("100870617373776f726406736563726574", in);
            check_int("C.2.3 (literal never indexed) decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_field("C.2.3: password: secret", &out[0], "password", "secret");
            check_int("C.2.3: dynamic table untouched (still empty)", t.count, 0);
        }
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[64]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[128]; size_t scratch_used;

            inlen = fromhex("82", in);
            check_int("C.2.4 (indexed header field, static table) decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_field("C.2.4: :method: GET", &out[0], ":method", "GET");
            check_int("C.2.4: dynamic table untouched (still empty)", t.count, 0);
        }

        /* RFC 7541 SS C.3 -- three consecutive requests on ONE connection,
         * the dynamic table growing across them: a literal-with-indexing
         * insertion in each of the first two requests, then that same
         * entry referenced back by a dynamic INDEX (62, then 63 once a
         * second insertion pushes it one further back) in the requests
         * that follow -- exactly "Indexed Dynamic Entries" from the
         * roadmap, verified against the RFC's own multi-step sequence
         * rather than a self-invented one. */
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[128]; int inlen;
            hpack_header_field out[8]; size_t out_count;
            uint8_t scratch[256]; size_t scratch_used;

            inlen = fromhex("828684410f7777772e6578616d706c652e636f6d", in);
            check_int("C.3.1 first request decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.3.1: 4 header fields decoded", (int)out_count, 4);
            check_field("C.3.1: :method: GET", &out[0], ":method", "GET");
            check_field("C.3.1: :scheme: http", &out[1], ":scheme", "http");
            check_field("C.3.1: :path: /", &out[2], ":path", "/");
            check_field("C.3.1: :authority: www.example.com (literal, indexed name)", &out[3], ":authority", "www.example.com");
            check_int("C.3.1: dynamic table has 1 entry", t.count, 1);
            check_int("C.3.1: dynamic table size is 57", (int)t.size, 57);

            inlen = fromhex("828684be58086e6f2d6361636865", in);
            check_int("C.3.2 second request decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.3.2: 5 header fields decoded", (int)out_count, 5);
            check_field("C.3.2: :authority (index 62, the entry C.3.1 just added)", &out[3], ":authority", "www.example.com");
            check_field("C.3.2: cache-control: no-cache (literal, indexed name)", &out[4], "cache-control", "no-cache");
            check_int("C.3.2: dynamic table has 2 entries", t.count, 2);
            check_int("C.3.2: dynamic table size is 110", (int)t.size, 110);

            inlen = fromhex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", in);
            check_int("C.3.3 third request decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.3.3: 5 header fields decoded", (int)out_count, 5);
            check_field("C.3.3: :scheme: https", &out[1], ":scheme", "https");
            check_field("C.3.3: :path: /index.html", &out[2], ":path", "/index.html");
            check_field("C.3.3: :authority (index 63 now -- pushed back by cache-control's insertion)", &out[3], ":authority", "www.example.com");
            check_field("C.3.3: custom-key: custom-value (literal name AND value)", &out[4], "custom-key", "custom-value");
            check_int("C.3.3: dynamic table has 3 entries", t.count, 3);
            check_int("C.3.3: dynamic table size is 164", (int)t.size, 164);
        }

        /* RFC 7541 SS C.5 -- three consecutive responses with
         * SETTINGS_HEADER_TABLE_SIZE=256, deliberately forcing real
         * evictions (including, in the third response, an entry that was
         * already referenced earlier in the SAME header block getting
         * evicted before the block finishes decoding -- exactly the case
         * that motivated always copying table-resolved bytes into
         * `scratch` rather than returning raw dynamic-table pointers). */
        {
            hpack_dyn_table t; hpack_table_init(&t, 256);
            uint8_t in[160]; int inlen;
            hpack_header_field out[8]; size_t out_count;
            uint8_t scratch[512]; size_t scratch_used;

            inlen = fromhex("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d", in);
            check_int("C.5.1 first response decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.5.1: 4 header fields decoded", (int)out_count, 4);
            check_field("C.5.1: :status: 302", &out[0], ":status", "302");
            check_field("C.5.1: cache-control: private", &out[1], "cache-control", "private");
            check_field("C.5.1: date", &out[2], "date", "Mon, 21 Oct 2013 20:13:21 GMT");
            check_field("C.5.1: location", &out[3], "location", "https://www.example.com");
            check_int("C.5.1: dynamic table has 4 entries", t.count, 4);
            check_int("C.5.1: dynamic table size is 222", (int)t.size, 222);

            inlen = fromhex("4803333037c1c0bf", in);
            check_int("C.5.2 second response decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.5.2: 4 header fields decoded", (int)out_count, 4);
            check_field("C.5.2: :status: 307 (its own insertion evicted the old :status:302 entry to fit)", &out[0], ":status", "307");
            check_field("C.5.2: cache-control (index 65, reused from response 1, not re-sent)", &out[1], "cache-control", "private");
            check_field("C.5.2: date (index 64, reused)", &out[2], "date", "Mon, 21 Oct 2013 20:13:21 GMT");
            check_field("C.5.2: location (index 63, reused)", &out[3], "location", "https://www.example.com");
            check_int("C.5.2: dynamic table still has 4 entries (one evicted, one added)", t.count, 4);
            check_int("C.5.2: dynamic table size still 222", (int)t.size, 222);

            inlen = fromhex("88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31", in);
            check_int("C.5.3 third response decodes", hpack_decode_headers(in, (size_t)inlen, &t, out, 8, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("C.5.3: 6 header fields decoded", (int)out_count, 6);
            check_field("C.5.3: :status: 200", &out[0], ":status", "200");
            check_field("C.5.3: cache-control (referenced by index, THEN evicted later in this same block)", &out[1], "cache-control", "private");
            check_field("C.5.3: date (a NEW date value, evicting the response-1 date entry to fit)", &out[2], "date", "Mon, 21 Oct 2013 20:13:22 GMT");
            check_field("C.5.3: location (referenced by index, THEN evicted later in this same block)", &out[3], "location", "https://www.example.com");
            check_field("C.5.3: content-encoding: gzip (evicts the just-added date-21 entry to fit)", &out[4], "content-encoding", "gzip");
            check_field("C.5.3: set-cookie (56-byte value; evicts two entries at once to fit)", &out[5], "set-cookie",
                       "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
            check_int("C.5.3: dynamic table has 3 entries (several evicted)", t.count, 3);
            check_int("C.5.3: dynamic table size is 215", (int)t.size, 215);
        }

        /* Dynamic Table Size Update (RFC 7541 SS6.3), exercised directly:
         * shrinking below the current size forces an eviction even with
         * no new entry being inserted. */
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            hpack_table_insert(&t, (const uint8_t*)"a", 1, (const uint8_t*)"1", 1);   /* size 34 */
            hpack_table_insert(&t, (const uint8_t*)"b", 1, (const uint8_t*)"2", 1);   /* size 34, total 68 */
            check_int("size update setup: 2 entries before shrinking", t.count, 2);
            check_int("hpack_table_set_max_size(34) evicts down to what fits", hpack_table_set_max_size(&t, 34), 0);
            check_int("size update: exactly 1 entry survives", t.count, 1);
            check_int("size update: the SURVIVING entry is the most recent ('b')", t.entries[0].name_len == 1 && t.arena[t.entries[0].name_off] == 'b', 1);
            check_int("hpack_table_set_max_size(0) evicts everything", hpack_table_set_max_size(&t, 0), 0);
            check_int("size update to 0: table is empty", t.count, 0);

            /* Wire-level: a Dynamic Table Size Update instruction (RFC
             * 7541 SS6.3: "001" + 5-bit-prefixed size) inside a real
             * header block, ahead of a literal insertion. */
            hpack_table_init(&t, 4096);
            uint8_t in[32]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[64]; size_t scratch_used;
            inlen = fromhex("3f01" "82", in);   /* size update to (31+1)=32, then indexed :method:GET */
            check_int("Dynamic Table Size Update instruction decodes inline", hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), 0);
            check_int("size update inline: only 1 header field emitted (the update itself emits none)", (int)out_count, 1);
            check_int("size update inline: table's max_size is now 32", (int)t.max_size, 32);
        }

        /* Malformed / out-of-range input -- all must fail loudly, not
         * corrupt state or silently produce a wrong result. */
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            uint8_t in[32]; int inlen;
            hpack_header_field out[4]; size_t out_count;
            uint8_t scratch[64]; size_t scratch_used;

            /* index 62 with an EMPTY dynamic table -- nothing to resolve. */
            inlen = fromhex("be", in);
            check_int("indexed field referencing an empty dynamic table is rejected",
                      hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), -1);

            /* index 0 is explicitly never used (RFC 7541 SS6.1). */
            inlen = fromhex("80", in);
            check_int("indexed field with index 0 is rejected",
                      hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), -1);

            /* a Dynamic Table Size Update past HPACK_DYN_ARENA_SIZE (4096)
             * claims a size this decoder never advertised being able to
             * support. */
            check_int("hpack_table_set_max_size() rejects a size past the arena cap",
                      hpack_table_set_max_size(&t, HPACK_DYN_ARENA_SIZE + 1), -1);

            /* a string literal whose declared length runs past the input. */
            inlen = fromhex("40" "ff" "0102", in);   /* literal name index=0; the length prefix (with continuation) decodes to 128, but only 2 bytes of the 4-byte input actually follow it */
            check_int("a string literal whose length overruns the input is rejected",
                      hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, scratch, sizeof scratch, &scratch_used), -1);

            /* out_cap too small for even one decoded field. */
            inlen = fromhex("82", in);
            check_int("out_cap of 0 rejects a block with any header field",
                      hpack_decode_headers(in, (size_t)inlen, &t, out, 0, &out_count, scratch, sizeof scratch, &scratch_used), -1);

            /* scratch too small for a literal string. */
            inlen = fromhex("400a637573746f6d2d6b65790d637573746f6d2d686561646572", in);
            uint8_t tiny_scratch[4];
            check_int("scratch too small for a decoded literal is rejected",
                      hpack_decode_headers(in, (size_t)inlen, &t, out, 4, &out_count, tiny_scratch, sizeof tiny_scratch, &scratch_used), -1);
        }

        /* hpack_table_get() directly -- static-only lookups, and the
         * unified index space boundary (61 = last static, 62 = first
         * dynamic). */
        {
            hpack_dyn_table t; hpack_table_init(&t, 4096);
            const uint8_t *name, *value; size_t name_len, value_len;

            check_int("hpack_table_get(8) resolves the static table", hpack_table_get(&t, 8, &name, &name_len, &value, &value_len), 0);
            check_int("hpack_table_get(8): name is :status", name_len == 7 && memcmp(name, ":status", 7) == 0, 1);
            check_int("hpack_table_get(8): value is 200", value_len == 3 && memcmp(value, "200", 3) == 0, 1);

            check_int("hpack_table_get(58) resolves user-agent (no static value)", hpack_table_get(&t, 58, &name, &name_len, &value, &value_len), 0);
            check_int("hpack_table_get(58): value_len is 0 (no static value)", (int)value_len, 0);

            check_int("hpack_table_get(0) is rejected", hpack_table_get(&t, 0, &name, &name_len, &value, &value_len), -1);
            check_int("hpack_table_get(62) on an empty dynamic table is rejected", hpack_table_get(&t, 62, &name, &name_len, &value, &value_len), -1);

            hpack_table_insert(&t, (const uint8_t*)"x-test", 6, (const uint8_t*)"v", 1);
            check_int("hpack_table_get(62) resolves the just-inserted entry", hpack_table_get(&t, 62, &name, &name_len, &value, &value_len), 0);
            check_int("hpack_table_get(62): name matches", name_len == 6 && memcmp(name, "x-test", 6) == 0, 1);
            check_int("hpack_table_get(63) (one past the only entry) is rejected", hpack_table_get(&t, 63, &name, &name_len, &value, &value_len), -1);
        }
    }

    printf(failures ? "\nHTTP/2 FRAME TEST: %d FAILURE(S)\n" : "\nHTTP/2 FRAME TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
