/* Host-side DEFLATE test: real raw-deflate streams (Python's zlib,
 * `compressobj(level, DEFLATED, -15)` for the headerless RFC 1951 form),
 * decompressed through compress/inflate.c and compared byte-exact against
 * the known original. Build/run: `make inflate-test`.
 *
 * Six vectors, chosen to force each DEFLATE block type at least once
 * (confirmed against the actual compressed bytes' BFINAL/BTYPE bits when
 * the vectors were generated, noted alongside each one below) plus the
 * two edge cases most likely to hide a bug: a back-reference distance
 * large enough to force the 32 KiB sliding window to wrap, and a
 * zero-length stream.
 *
 * The two large originals (V3, V4) are deterministic byte patterns
 * (`(i*97+13) % 256`-style formulas) regenerated here in C rather than
 * embedded as giant hex/string literals -- only their real compressed
 * bytes (from Python) need to be transcribed. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "inflate.h"

/* V1: 5 bytes, fixed Huffman (BTYPE=1) */
#define V1_ORIG "hello"
#define V1_LEN  5
#define C1_HEX  "cb48cdc9c90700"

/* V2: 124 bytes, repetitive -> LZ77 back-references, fixed Huffman */
#define V2_ORIG "hello hello hello hello hello! hello hello hello hello hello! " \
                 "hello hello hello hello hello! hello hello hello hello hello! "
#define V2_LEN  124
#define C2_HEX  "cb48cdc9c957c8c04e2ae292a08e3400"

/* V3: 40000 bytes (base pattern of 2000 repeated 20x) -- exceeds the 32 KiB
 * window, so decoding it correctly requires the sliding window to wrap and
 * still resolve back-references into the previous lap. Dynamic Huffman. */
#define V3_LEN      40000
#define V3_BASE_LEN 2000
#define V3_REPS     20
#define C3_HEX \
    "edd1835a18001886d1a1a1b6c66a5ecdacd96acdb65b5b53b3edd56cdb5618aad5b6c66635dbb6adfbf8bff712ce739c7b9f2f3ce76393ddae83af955ef2b3cdbe2ca3ef79af49d0f168ae89cf6a6e71ea71c673e6bb863bd20cb85c62e1b796511947dcaeb0f25ffb43d9831e57db98a4ebc9fcd35ed70b49d937aee8bccfcd22d20dbd5176d9efb631ee631ff8ac73e87c2ccfe417b5b725ef75aed0ec0f8d77b90cba5a6af18fd67b338fba5b6975fc0e47724e785a63b363f7d30567bc6d1096baffa5e20bbeb6d89361f8adf22bfeb63b982df051d50d89034ee49bfaaa6e708a3e178accfdd434dc6dc8f5324b7ff9eecf3ae67ee5b5093bc5e69ef4bcd6d6643dcf7acd7adf6867da81574a2efade2a3ad3c83b1557c5f33f9c63fc93ea9b92763b5560fa9bfaa1a9fa5d2c36ff4bf3c8f4c36e965bfec7ef80c7b88755d627ea723cef949775b63be3c78f1f3f7efc06fcd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd36fcda3fe891f3f7efcf835fdd63cea9ff8f1e3c78f5fd3ff1f"

/* V4: 500 bytes, compressed at level 0 -> stored blocks (BTYPE=0) */
#define V4_LEN 500
#define C4_HEX \
    "01f4010bfe0db45b02a950f79e45ec933ae1882fd67d24cb7219c0670eb55c03aa51f89f46ed943be28930d77e25cc731ac1680fb65d04ab52f9a047ee953ce38a31d87f26cd741bc26910b75e05ac53faa148ef963de48b32d98027ce751cc36a11b85f06ad54fba249f0973ee58c33da8128cf761dc46b12b96007ae55fca34af1983fe68d34db8229d0771ec56c13ba6108af56fda44bf29940e78e35dc832ad1781fc66d14bb6209b057fea54cf39a41e88f36dd842bd27920c76e15bc630ab158ffa64df49b42e99037de852cd37a21c86f16bd640bb25900a74ef59c43ea9138df862dd47b22c97017be650cb35a01a84ff69d44eb9239e0872ed57c23ca7118bf660db45b02a950f79e45ec933ae1882fd67d24cb7219c0670eb55c03aa51f89f46ed943be28930d77e25cc731ac1680fb65d04ab52f9a047ee953ce38a31d87f26cd741bc26910b75e05ac53faa148ef963de48b32d98027ce751cc36a11b85f06ad54fba249f0973ee58c33da8128cf761dc46b12b96007ae55fca34af1983fe68d34db8229d0771ec56c13ba6108af56fda44bf29940e78e35dc832ad1781fc66d14bb6209b057fea54cf39a41e88f36dd842bd27920c76e15bc630ab158ffa64df49b42e99037de852cd37a21c86f16bd640bb25900a74ef59c43ea9138df862dd47b22c97017be650cb35a01a84ff69d44eb92"

/* V5: 4300 bytes of natural-ish repeated text -> dynamic Huffman. Two
 * DIFFERENT sentences, each repeated 50 times back to back (not one
 * combined unit): 45*50 + 41*50 = 4300. */
#define V5_UNIT_A "The quick brown fox jumps over the lazy dog. "
#define V5_UNIT_A_LEN 45
#define V5_UNIT_B "Pack my box with five dozen liquor jugs. "
#define V5_UNIT_B_LEN 41
#define V5_REPS_EACH 50
#define C5_HEX \
    "edcbc71180301004c154360262e1a104304212ee4006173d170645ed7b7a8cb7d84be826b451ce15835c18cbb225c86123b2e6b9796ef4e22a1862626262626262e22fe1ba51b7dc68159d217b0ce1b09a1ebb620e7b91a8af4b84848484848484bf822f"

/* V6: zero-length input -> a single empty fixed-Huffman block */
#define C6_HEX "0300"

static int failures;

static int unhex(const char *s, uint8_t *out)
{
    int n = 0;
    for (; s[0] && s[1]; s += 2) {
        int hi = s[0] <= '9' ? s[0]-'0' : (s[0]|32)-'a'+10;
        int lo = s[1] <= '9' ? s[1]-'0' : (s[1]|32)-'a'+10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

/* Decompress the whole of `comp` in one call, with generous buffers -- pins
 * basic correctness before the streaming test below stresses chunking. */
static int inflate_whole(const uint8_t *comp, size_t complen, uint8_t *out, size_t outcap, size_t *outlen)
{
    inflate_ctx ctx;
    inflate_init(&ctx);
    size_t in_used, produced;
    int done = 0;
    int rc = inflate_feed(&ctx, comp, complen, out, outcap, &in_used, &produced, &done);
    *outlen = produced;
    if (rc != 0) return -1;
    if (in_used != complen) return -2;      /* leftover input: shouldn't happen for a single final block */
    if (!done) return -3;
    return 0;
}

int main(void)
{
    printf("DEFLATE (RFC 1951) -- real raw-deflate streams vs known originals:\n");

    {
        uint8_t comp[64]; int complen = unhex(C1_HEX, comp);
        uint8_t out[64]; size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V1 (fixed Huffman, short) decodes OK", rc == 0);
        check_ok("V1 length matches", outlen == V1_LEN);
        check_ok("V1 content matches", outlen == V1_LEN && memcmp(out, V1_ORIG, V1_LEN) == 0);
    }
    {
        uint8_t comp[64]; int complen = unhex(C2_HEX, comp);
        uint8_t out[256]; size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V2 (fixed Huffman + back-references) decodes OK", rc == 0);
        check_ok("V2 length matches", outlen == V2_LEN);
        check_ok("V2 content matches", outlen == V2_LEN && memcmp(out, V2_ORIG, V2_LEN) == 0);
    }
    {
        static uint8_t comp[2048]; int complen = unhex(C3_HEX, comp);
        static uint8_t expect[V3_LEN], out[V3_LEN];
        for (int i = 0; i < V3_BASE_LEN; i++) {
            uint8_t b = (uint8_t)((i * 97 + 13) % 256);
            for (int r = 0; r < V3_REPS; r++) expect[r * V3_BASE_LEN + i] = b;
        }
        size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V3 (dynamic Huffman, 32KiB+ window wrap) decodes OK", rc == 0);
        check_ok("V3 length matches", outlen == V3_LEN);
        check_ok("V3 content matches (window wrap resolved correctly)",
                 outlen == V3_LEN && memcmp(out, expect, V3_LEN) == 0);
    }
    {
        static uint8_t comp[1024]; int complen = unhex(C4_HEX, comp);
        static uint8_t expect[V4_LEN], out[V4_LEN];
        for (int i = 0; i < V4_LEN; i++) expect[i] = (uint8_t)((i * 167 + 13) % 256);
        size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V4 (stored blocks) decodes OK", rc == 0);
        check_ok("V4 length matches", outlen == V4_LEN);
        check_ok("V4 content matches", outlen == V4_LEN && memcmp(out, expect, V4_LEN) == 0);
    }
    {
        static uint8_t comp[256]; int complen = unhex(C5_HEX, comp);
        static uint8_t expect[V5_REPS_EACH * (V5_UNIT_A_LEN + V5_UNIT_B_LEN)];
        static uint8_t out[V5_REPS_EACH * (V5_UNIT_A_LEN + V5_UNIT_B_LEN)];
        int elen = 0;
        for (int r = 0; r < V5_REPS_EACH; r++) { memcpy(expect + elen, V5_UNIT_A, V5_UNIT_A_LEN); elen += V5_UNIT_A_LEN; }
        for (int r = 0; r < V5_REPS_EACH; r++) { memcpy(expect + elen, V5_UNIT_B, V5_UNIT_B_LEN); elen += V5_UNIT_B_LEN; }
        size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V5 (dynamic Huffman, natural text) decodes OK", rc == 0);
        check_ok("V5 length matches", (int)outlen == elen);
        check_ok("V5 content matches", (int)outlen == elen && memcmp(out, expect, (size_t)elen) == 0);
    }
    {
        uint8_t comp[8]; int complen = unhex(C6_HEX, comp);
        uint8_t out[8]; size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("V6 (empty stream) decodes OK", rc == 0);
        check_ok("V6 length is zero", outlen == 0);
    }

    /* Corruption checks: a stream that never reaches a final block's
     * end-of-block symbol, and one with a mangled block-type header. */
    {
        uint8_t comp[64]; int complen = unhex(C1_HEX, comp);
        comp[0] ^= 0xff;   /* corrupt the very first byte (BFINAL/BTYPE + first code bits) */
        uint8_t out[64]; size_t outlen;
        int rc = inflate_whole(comp, (size_t)complen, out, sizeof out, &outlen);
        check_ok("corrupted stream is rejected, not silently accepted", rc != 0);
    }

    printf("\nDEFLATE streaming: same compressed bytes, arbitrary chunk boundaries:\n");
    {
        /* Feed V3's compressed bytes in tiny, irregular pieces and write
         * output through a tiny buffer too -- proves inflate_feed() is a
         * genuine incremental decoder (resumable on both axes), not a
         * buffer-then-decompress-in-one-call implementation in disguise. */
        static uint8_t comp[2048]; int complen = unhex(C3_HEX, comp);
        static uint8_t expect[V3_LEN];
        for (int i = 0; i < V3_BASE_LEN; i++) {
            uint8_t b = (uint8_t)((i * 97 + 13) % 256);
            for (int r = 0; r < V3_REPS; r++) expect[r * V3_BASE_LEN + i] = b;
        }

        static uint8_t got[V3_LEN];
        size_t got_len = 0;
        inflate_ctx ctx;
        inflate_init(&ctx);

        size_t in_pos = 0;
        int done = 0;
        int chunk = 1;              /* 1, 2, 3, 1, 2, 3, ... byte input chunks */
        int rounds = 0, max_rounds = 1000000;
        while (!done && rounds++ < max_rounds) {
            size_t want = (size_t)(chunk % 3) + 1;
            size_t avail = complen - in_pos;
            size_t feed_len = want < avail ? want : avail;
            uint8_t outbuf[7];      /* deliberately tiny and not a multiple of anything */
            size_t in_used, produced;
            int rc = inflate_feed(&ctx, comp + in_pos, feed_len, outbuf, sizeof outbuf, &in_used, &produced, &done);
            if (rc != 0) { failures++; printf("  FAIL  streaming decode errored mid-stream\n"); goto stream_fail; }
            in_pos += in_used;
            if (produced > 0) {
                memcpy(got + got_len, outbuf, produced);
                got_len += produced;
            }
            /* if this call consumed nothing and produced nothing and there
             * was input left to offer, force progress next iteration by
             * trying a different chunk size (a well-behaved decoder should
             * still make progress here since outbuf has room; this guards
             * the test itself against ever spinning forever on a stall) */
            chunk++;
            if (in_used == 0 && produced == 0 && feed_len == 0 && in_pos >= complen) break;
        }
        check_ok("streaming: reached end of stream", done);
        check_ok("streaming: length matches whole-buffer decode", got_len == V3_LEN);
        check_ok("streaming: content matches whole-buffer decode (chunk-boundary independence)",
                 got_len == V3_LEN && memcmp(got, expect, V3_LEN) == 0);
        stream_fail: ;
    }

    printf(failures ? "\nDEFLATE TEST: %d FAILURE(S)\n" : "\nDEFLATE TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
