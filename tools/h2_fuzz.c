/* HTTP/2 fuzz harness (Phase 17.5.1) -- feeds random and deliberately
 * malformed bytes into every http2/ decode entry point (the only code in
 * this project that ever has to trust bytes a network peer produced) and
 * checks two things about each call: it never crashes (a segfault, an
 * assertion failure, or -- when built with `make h2-fuzz-san`, see the
 * Makefile -- a sanitizer-detected out-of-bounds read/write or undefined
 * behavior), and every documented invariant about its OUTPUT still holds
 * (a decoded count never exceeds the capacity it was given, a returned
 * pointer always falls inside the buffer it's supposed to point into).
 * The second check matters as much as the first: a function that reads
 * out of bounds without a sanitizer to notice, or that returns a byte
 * count larger than the buffer it just filled, is exactly the kind of bug
 * a plain "did it crash" fuzz run would miss.
 *
 * Deterministic by default (a fixed seed, printed on every run) so a
 * discovered failure is exactly reproducible -- pass a seed as argv[1] to
 * explore a different stream, or ITERS as argv[2] to run more/fewer
 * rounds per target.
 *
 * Freestanding-safe production code (the http2 directory) is exercised
 * as-is, built the same way `make h2-test` already does; this file itself
 * is a host tool like every other file under tools/, free to use the
 * full host libc. */
#include <stdio.h>
#include <stdlib.h>
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
#include "window_update.h"

#define DEFAULT_SEED  0x4155524fu   /* "AURO" -- arbitrary, just needs to be fixed */
#define DEFAULT_ITERS 200000u

static uint64_t g_rng;

static uint64_t xorshift64(void)
{
    uint64_t x = g_rng;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_rng = x;
    return x;
}

static void fill_random(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(xorshift64() & 0xFF);
}

/* A length biased toward the small end (where most real protocol data
 * lives, and where off-by-one boundary bugs actually hide) but occasionally
 * reaching up toward `max` -- a uniform distribution would spend almost
 * all its time on lengths no real caller would ever pass. */
static size_t random_len(size_t max)
{
    uint64_t r = xorshift64();
    size_t small = (size_t)(r % 64);
    if ((r >> 32) % 8 == 0) return (size_t)((r >> 16) % (max + 1));
    return small > max ? max : small;
}

static int g_failures;

static void report(const char *target, uint64_t iter, const char *what,
                   const uint8_t *input, size_t input_len)
{
    fprintf(stderr, "FUZZ FAILURE [%s] iteration %llu: %s\n", target, (unsigned long long)iter, what);
    fprintf(stderr, "  input (%zu bytes): ", input_len);
    for (size_t i = 0; i < input_len && i < 256; i++) fprintf(stderr, "%02x", input[i]);
    if (input_len > 256) fprintf(stderr, "...(truncated)");
    fprintf(stderr, "\n  reproduce with: seed=%llu\n", (unsigned long long)g_rng);
    g_failures++;
}

/* ------------------------------------------------------------------ */
/* Target 1: the generic frame reader -- random bytes fed as if freshly */
/* arrived off the wire, draining whatever frames come out.            */
/* ------------------------------------------------------------------ */
static void fuzz_frame_reader(uint64_t iters)
{
    uint8_t chunk[4096];
    for (uint64_t it = 0; it < iters; it++) {
        h2_frame_reader r;
        h2_frame_reader_init(&r);
        size_t clen = random_len(sizeof chunk);
        fill_random(chunk, clen);

        size_t pos = 0;
        int rounds = 0;
        while (pos < clen && rounds++ < 4096) {
            int fed = h2_frame_reader_feed(&r, chunk + pos, clen - pos);
            if (fed < -1 || fed > (int)(clen - pos)) {
                report("frame_reader", it, "feed() returned an out-of-range count", chunk, clen);
                break;
            }
            if (fed < 0) break;   /* frame size error -- a valid, expected outcome */
            if (fed == 0) break;  /* needs more bytes than this chunk has left */
            pos += (size_t)fed;

            h2_frame_header fh; const uint8_t *payload; size_t payload_len;
            while (h2_frame_reader_next(&r, &fh, &payload, &payload_len) == 1) {
                if (payload_len > H2_FRAME_PAYLOAD_MAX) {
                    report("frame_reader", it, "next() returned a payload_len past H2_FRAME_PAYLOAD_MAX", chunk, clen);
                }
                if (fh.stream_id > 0x7FFFFFFFu) {
                    report("frame_reader", it, "next() returned a stream_id with the reserved bit set", chunk, clen);
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Target 2: HPACK header-block decode -- random bytes as a header      */
/* block, including some deliberately shaped to set the Huffman bit on  */
/* string literals, so malformed Huffman content flows through the same */
/* path a real (if buggy or hostile) HEADERS frame would use.           */
/* ------------------------------------------------------------------ */
static void fuzz_hpack_decode(uint64_t iters)
{
    uint8_t block[2048];
    hpack_header_field out[64];
    uint8_t scratch[4096];

    for (uint64_t it = 0; it < iters; it++) {
        hpack_dyn_table table;
        hpack_table_init(&table, HPACK_DYN_ARENA_SIZE);

        size_t blen = random_len(sizeof block);
        fill_random(block, blen);
        /* Bias roughly a quarter of the representation-leading bytes
         * toward the "0000xxxx"/"01xxxxxx" shapes whose very next byte is
         * a string-literal length+Huffman-bit -- otherwise most random
         * bytes land on Indexed Header Field (top bit set) and never
         * reach the Huffman decoder at all. */
        if (blen > 2 && (xorshift64() % 4) == 0) {
            block[0] = (uint8_t)(0x40 | (block[0] & 0x0F));   /* Literal w/ Incremental Indexing, small name index */
            block[1] |= 0x80;                                  /* force the value's Huffman bit on */
        }

        size_t nfields = 0, scratch_used = 0;
        int rc = hpack_decode_headers(block, blen, &table, out, 64, &nfields, scratch, sizeof scratch, &scratch_used);
        if (rc == 0) {
            if (nfields > 64) report("hpack_decode", it, "out_count exceeds out_cap", block, blen);
            if (scratch_used > sizeof scratch) report("hpack_decode", it, "scratch_used exceeds scratch_cap", block, blen);
            for (size_t i = 0; i < nfields && i < 64; i++) {
                const hpack_header_field *f = &out[i];
                if (f->name && (f->name < scratch || f->name + f->name_len > scratch + sizeof scratch))
                    report("hpack_decode", it, "a decoded field's name pointer falls outside scratch[]", block, blen);
                if (f->value && (f->value < scratch || f->value + f->value_len > scratch + sizeof scratch))
                    report("hpack_decode", it, "a decoded field's value pointer falls outside scratch[]", block, blen);
            }
        } else if (rc != -1) {
            report("hpack_decode", it, "returned something other than 0 or -1", block, blen);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Target 3: Huffman decode directly -- corrupted/random Huffman-coded  */
/* byte strings, independent of the HPACK framing around them.          */
/* ------------------------------------------------------------------ */
static void fuzz_huffman(uint64_t iters)
{
    uint8_t in[512], out[2048];
    for (uint64_t it = 0; it < iters; it++) {
        size_t ilen = random_len(sizeof in);
        fill_random(in, ilen);
        size_t outlen = 0;
        int rc = hpack_huffman_decode(in, ilen, out, sizeof out, &outlen);
        if (rc == 0 && outlen > sizeof out) {
            report("huffman", it, "outlen exceeds outcap", in, ilen);
        } else if (rc != 0 && rc != -1) {
            report("huffman", it, "returned something other than 0 or -1", in, ilen);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Target 4: DATA frame parsing -- random payloads, padded and not.     */
/* ------------------------------------------------------------------ */
static void fuzz_data_parse(uint64_t iters)
{
    uint8_t payload[2048];
    for (uint64_t it = 0; it < iters; it++) {
        size_t plen = random_len(sizeof payload);
        fill_random(payload, plen);
        uint8_t flags = (uint8_t)(xorshift64() % 2 ? H2_FLAG_PADDED : 0);

        const uint8_t *data = NULL; size_t data_len = 0;
        int rc = h2_data_parse(payload, plen, flags, &data, &data_len);
        if (rc == 0) {
            if (data_len > plen) report("data_parse", it, "data_len exceeds the input payload length", payload, plen);
            if (data && (data < payload || data + data_len > payload + plen))
                report("data_parse", it, "returned data pointer falls outside the input payload", payload, plen);
        } else if (rc != -1) {
            report("data_parse", it, "returned something other than 0 or -1", payload, plen);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Target 5: SETTINGS payload length validation -- every possible       */
/* 24-bit length value is nominally in range, so this sweeps randomly    */
/* rather than exhaustively; the function takes no buffer, just a       */
/* length, so there's no bounds invariant beyond "returns 0 or 1".      */
/* ------------------------------------------------------------------ */
static void fuzz_settings(uint64_t iters)
{
    for (uint64_t it = 0; it < iters; it++) {
        uint32_t len = (uint32_t)(xorshift64() & 0xFFFFFFu);   /* full 24-bit frame length range */
        int rc = h2_settings_payload_valid(len);
        if (rc != 0 && rc != 1) {
            uint8_t dummy[4]; memcpy(dummy, &len, 4);
            report("settings", it, "returned something other than 0 or 1", dummy, 4);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Target 6: WINDOW_UPDATE parsing -- random 4-byte (and occasionally    */
/* wrong-length) payloads.                                              */
/* ------------------------------------------------------------------ */
static void fuzz_window_update(uint64_t iters)
{
    uint8_t payload[16];
    for (uint64_t it = 0; it < iters; it++) {
        size_t plen = (xorshift64() % 8 == 0) ? random_len(sizeof payload) : 4;   /* mostly 4, sometimes not */
        fill_random(payload, plen);
        uint32_t increment = 0;
        int rc = h2_window_update_parse(payload, plen, &increment);
        if (rc == 0) {
            if (increment == 0 || increment > 0x7FFFFFFFu)
                report("window_update", it, "parsed an increment outside RFC 7541 SS6.9's valid range", payload, plen);
        } else if (rc != -1) {
            report("window_update", it, "returned something other than 0 or -1", payload, plen);
        }
    }
}

int main(int argc, char **argv)
{
    uint64_t seed = argc > 1 ? strtoull(argv[1], NULL, 0) : DEFAULT_SEED;
    uint64_t iters = argc > 2 ? strtoull(argv[2], NULL, 0) : DEFAULT_ITERS;
    if (seed == 0) seed = 1;   /* xorshift64 never recovers from an all-zero state */
    g_rng = seed;

    printf("HTTP/2 fuzz harness (Phase 17.5.1) -- seed=%llu iters/target=%llu\n",
          (unsigned long long)seed, (unsigned long long)iters);

    fuzz_frame_reader(iters);
    printf("  frame_reader: %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);
    fuzz_hpack_decode(iters);
    printf("  hpack_decode: %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);
    fuzz_huffman(iters);
    printf("  huffman:      %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);
    fuzz_data_parse(iters);
    printf("  data_parse:   %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);
    fuzz_settings(iters);
    printf("  settings:     %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);
    fuzz_window_update(iters);
    printf("  window_update: %llu iterations, %d failures so far\n", (unsigned long long)iters, g_failures);

    printf(g_failures ? "\nHTTP/2 FUZZ: %d FAILURE(S)\n" : "\nHTTP/2 FUZZ: ALL PASS (no crash, no invariant violation)\n", g_failures);
    return g_failures ? 1 : 0;
}
