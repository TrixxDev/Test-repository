/* DEFLATE decompression (RFC 1951), genuinely incremental: a caller feeds
 * compressed bytes as they arrive (e.g. off a TCP socket) and pulls
 * decompressed bytes into whatever output buffer it currently has room for
 * -- neither the whole compressed input nor the whole decompressed output
 * ever needs to sit in memory at once. Portable, freestanding: only
 * <stdint.h>/<stddef.h>, no allocation, no OS calls -- same discipline as
 * crypto/ and tls/.
 *
 * The algorithm (canonical-Huffman table construction + bit-at-a-time
 * decode) follows the well-known reference structure of Mark Adler's
 * public-domain puff.c, the zlib author's own minimal supplement to RFC
 * 1951 -- but restructured throughout into an explicit state machine so
 * every step can pause on "need more input" or "output buffer full" and
 * resume exactly where it left off on the next inflate_feed() call, which
 * puff.c (a whole-buffer-at-once reference decoder) does not need to do. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define INFLATE_WINDOW      32768u                       /* RFC 1951 max back-reference distance */
#define INFLATE_MAXBITS     15                            /* longest Huffman code RFC 1951 allows */
#define INFLATE_MAXLCODES   286                            /* literal/length alphabet, symbols 0..285 */
#define INFLATE_MAXDCODES   30                             /* distance alphabet, symbols 0..29 */
#define INFLATE_MAXCODES    (INFLATE_MAXLCODES + INFLATE_MAXDCODES)

/* A canonical Huffman table (RFC 1951 §3.2.2): count[len] = how many codes
 * of that length exist; symbol[] holds the symbols in the order the
 * decoder's bit-at-a-time walk expects (grouped by length, then by code
 * value within a length). Sized for the largest table needed (the fixed
 * distance table's 32 codes, or a dynamic literal/length table's 286). */
typedef struct {
    uint16_t count[INFLATE_MAXBITS + 1];
    uint16_t symbol[INFLATE_MAXLCODES];
} inflate_huff;

typedef enum {
    INF_BLOCK_HDR = 0,
    INF_STORED_LEN,
    INF_STORED_COPY,
    INF_DYN_HDR,
    INF_DYN_CLLEN,
    INF_DYN_LENGTHS,
    INF_DECODE_SYM,
    INF_LEN_EXTRA,
    INF_DECODE_DIST,
    INF_DIST_EXTRA,
    INF_COPY,
    INF_BLOCK_DONE,
    INF_DONE,
    INF_ERROR
} inflate_mode;

typedef struct {
    /* bit reader: bitbuf holds bitcnt valid bits, next bit to consume is
     * bit 0 (LSB) -- RFC 1951 §3.1.1 packs bits LSB-first within a byte. */
    uint32_t bitbuf;
    int      bitcnt;

    /* the CURRENT feed() call's input; re-pointed at the top of every call */
    const uint8_t *in;
    size_t in_pos, in_len;

    /* sliding window: also doubles as the record of every byte already
     * delivered to the caller, since a back-reference can point at output
     * produced in an earlier inflate_feed() call. */
    uint8_t window[INFLATE_WINDOW];
    size_t  window_pos;      /* next write position, mod INFLATE_WINDOW      */
    size_t  window_filled;   /* valid history bytes so far, capped at the window size */

    inflate_mode mode;
    int final_block;

    /* stored (BTYPE=00) block */
    uint32_t stored_left;

    /* dynamic (BTYPE=10) header parsing */
    unsigned hlit, hdist, hclen;
    unsigned ncode;
    uint8_t  cl_lens[19];
    uint16_t lens[INFLATE_MAXCODES];
    unsigned nlens;
    int      pending_cl_sym;   /* a decoded code-length symbol (16/17/18) whose
                                 * extra bits haven't been read yet, or -1 */
    inflate_huff cl_table, lit_table, dist_table;

    /* resumable canonical-Huffman symbol decode, shared by cl/lit/dist --
     * only one is ever in flight at a time. Reset to (1,0,0,0) on every
     * successful decode, so it's always ready for the next table's use. */
    int h_len, h_code, h_first, h_index;

    /* pending length/distance for the match currently being assembled */
    int      len_sym, dist_sym;
    unsigned match_len, match_dist;

    /* resumable output copy: a literal (copy_dist == 0) or a back-reference
     * (copy_dist >= 1) drains through the exact same loop, byte by byte,
     * which is what makes overlapping runs (distance < length) come out
     * right without special-casing them. */
    unsigned copy_remaining;
    unsigned copy_dist;
    uint8_t  copy_literal;
} inflate_ctx;

void inflate_init(inflate_ctx *ctx);

/* Feed `in_len` new compressed bytes and decompress into `out` (capacity
 * `out_cap`), processing as much as fits in one call:
 *   *in_used  -- bytes of `in` actually consumed (may be < in_len if `out`
 *                filled up first; re-feed the remainder next call)
 *   *out_len  -- decompressed bytes written to `out` this call
 *   *done     -- set to 1 once the final block's end has been reached (no
 *                further output will ever be produced by this stream)
 * Returns 0 (including "no progress possible yet, call again with more
 * input or output room" -- that is not an error) or -1 on a malformed
 * stream, after which `ctx` is stuck in an error state (start a fresh one
 * to recover; there is nothing to resume). */
int inflate_feed(inflate_ctx *ctx, const uint8_t *in, size_t in_len,
                 uint8_t *out, size_t out_cap,
                 size_t *in_used, size_t *out_len, int *done);
