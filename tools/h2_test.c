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

static int failures;

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

    printf(failures ? "\nHTTP/2 FRAME TEST: %d FAILURE(S)\n" : "\nHTTP/2 FRAME TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
