/* Host-side HTTP/2 frame layer test (http2/: RFC 7540 §4.1 frame header,
 * §6.5 SETTINGS). No networking -- pure byte<->struct, exercised entirely
 * on the host. Build/run: `make h2-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "frame.h"
#include "settings.h"

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

    printf(failures ? "\nHTTP/2 FRAME TEST: %d FAILURE(S)\n" : "\nHTTP/2 FRAME TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
