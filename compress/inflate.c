/* DEFLATE decompression (RFC 1951) -- see inflate.h. */
#include "inflate.h"

/* RFC 1951 §3.2.5: length code 257..285 -> base length + extra bits, and
 * distance code 0..29 -> base distance + extra bits. Transcribed directly
 * from the RFC's own tables (verified against the published text, not
 * carried over from memory of other implementations). */
static const uint16_t LBASE[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t LEXT[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t DBASE[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};
static const uint8_t DEXT[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
/* RFC 1951 §3.2.7: the order code-length codes 0..18 are transmitted in. */
static const uint8_t CLORDER[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/* Canonical Huffman table construction (RFC 1951 §3.2.2). Returns 0 for a
 * complete code, a positive count of unused code space for an incomplete
 * one (the caller decides whether that's tolerable -- RFC 1951 explicitly
 * allows exactly one case of this, a single 1-bit distance code), or -1 if
 * over-subscribed (never valid). */
static int huff_build(inflate_huff *h, const uint16_t *lens, unsigned n)
{
    for (int i = 0; i <= INFLATE_MAXBITS; i++) h->count[i] = 0;
    for (unsigned i = 0; i < n; i++) h->count[lens[i]]++;
    if (h->count[0] == n) return 0;   /* empty table: no symbols at all */

    int left = 1;
    for (int len = 1; len <= INFLATE_MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return -1;      /* over-subscribed: never valid */
    }

    uint16_t offs[INFLATE_MAXBITS + 1];
    offs[1] = 0;
    for (int len = 1; len < INFLATE_MAXBITS; len++) offs[len + 1] = (uint16_t)(offs[len] + h->count[len]);
    for (unsigned i = 0; i < n; i++)
        if (lens[i] != 0) h->symbol[offs[lens[i]]++] = (uint16_t)i;

    return left;
}

/* An incomplete code (huff_build() > 0) is tolerated only for the single
 * case RFC 1951 §3.2.7 names explicitly: exactly one real code, of length
 * 1 (the "no distance codes used, or exactly one" degenerate case). */
static int huff_ok(int build_rc, const inflate_huff *h, unsigned n)
{
    if (build_rc == 0) return 1;
    if (build_rc < 0) return 0;
    return (unsigned)(h->count[0] + h->count[1]) == n;
}

static void window_put(inflate_ctx *c, uint8_t b)
{
    c->window[c->window_pos] = b;
    c->window_pos = (c->window_pos + 1) % INFLATE_WINDOW;
    if (c->window_filled < INFLATE_WINDOW) c->window_filled++;
}

static int ensure_bits(inflate_ctx *c, int n)
{
    while (c->bitcnt < n) {
        if (c->in_pos >= c->in_len) return 0;
        c->bitbuf |= (uint32_t)c->in[c->in_pos++] << c->bitcnt;
        c->bitcnt += 8;
    }
    return 1;
}

static uint32_t take_bits(inflate_ctx *c, int n)
{
    uint32_t v = c->bitbuf & (uint32_t)((1u << n) - 1u);
    c->bitbuf >>= n;
    c->bitcnt -= n;
    return v;
}

/* One bit at a time, canonical-Huffman decode (the classic count/symbol-
 * table walk). Resumable: h_len/h_code/h_first/h_index persist in `c`
 * across a "need more input" pause and pick up exactly where they left
 * off; a successful decode resets them, leaving the fields ready for
 * whichever table's decode comes next. Returns 1 with *sym set, 0 if more
 * input is needed (state saved), -1 on a corrupt code (no valid symbol). */
static int decode_symbol(inflate_ctx *c, const inflate_huff *h, int *sym)
{
    for (;;) {
        if (c->bitcnt == 0) {
            if (c->in_pos >= c->in_len) return 0;
            c->bitbuf = (uint32_t)c->in[c->in_pos++];
            c->bitcnt = 8;
        }
        if (c->h_len > INFLATE_MAXBITS) return -1;
        int bit = (int)(c->bitbuf & 1);
        c->bitbuf >>= 1;
        c->bitcnt--;
        c->h_code |= bit;
        int count = h->count[c->h_len];
        if (c->h_code - count < c->h_first) {
            *sym = h->symbol[c->h_index + (c->h_code - c->h_first)];
            c->h_len = 1; c->h_code = 0; c->h_first = 0; c->h_index = 0;
            return 1;
        }
        c->h_index += count;
        c->h_first = (c->h_first + count) << 1;
        c->h_code <<= 1;
        c->h_len++;
    }
}

static void build_fixed_tables(inflate_ctx *c)
{
    uint16_t lens[288];
    int i = 0;
    for (; i < 144; i++) lens[i] = 8;
    for (; i < 256; i++) lens[i] = 9;
    for (; i < 280; i++) lens[i] = 7;
    for (; i < 288; i++) lens[i] = 8;
    huff_build(&c->lit_table, lens, 288);   /* always complete: exact power-of-two fit */

    /* RFC 1951 §3.2.6: distance codes 0..31 get fixed 5-bit codes (all 32
     * slots, even though symbols 30/31 never legitimately occur) -- using
     * only 30 here would leave 2 codes of unused space and wrongly report
     * an "incomplete" table for every fixed-Huffman block. */
    for (i = 0; i < 32; i++) lens[i] = 5;
    huff_build(&c->dist_table, lens, 32);
}

void inflate_init(inflate_ctx *ctx)
{
    ctx->bitbuf = 0; ctx->bitcnt = 0;
    ctx->window_pos = 0; ctx->window_filled = 0;
    ctx->mode = INF_BLOCK_HDR;
    ctx->final_block = 0;
    ctx->pending_cl_sym = -1;
    ctx->h_len = 1; ctx->h_code = 0; ctx->h_first = 0; ctx->h_index = 0;
}

int inflate_feed(inflate_ctx *c, const uint8_t *in, size_t in_len,
                 uint8_t *out, size_t out_cap,
                 size_t *in_used, size_t *out_len, int *done)
{
    c->in = in; c->in_pos = 0; c->in_len = in_len;
    size_t produced = 0;

    if (c->mode == INF_DONE)  { *in_used = 0; *out_len = 0; *done = 1; return 0; }
    if (c->mode == INF_ERROR) { *in_used = 0; *out_len = 0; *done = 0; return -1; }

    for (;;) {
        switch (c->mode) {

        case INF_BLOCK_HDR: {
            if (!ensure_bits(c, 3)) goto need_input;
            c->final_block = (int)take_bits(c, 1);
            unsigned btype = take_bits(c, 2);
            if (btype == 0) {
                int drop = c->bitcnt & 7;               /* byte-align before LEN/NLEN */
                c->bitbuf >>= drop; c->bitcnt -= drop;
                c->mode = INF_STORED_LEN;
            } else if (btype == 1) {
                build_fixed_tables(c);
                c->mode = INF_DECODE_SYM;
            } else if (btype == 2) {
                c->mode = INF_DYN_HDR;
            } else {
                goto error;                              /* BTYPE 11 is reserved */
            }
            continue;
        }

        case INF_STORED_LEN: {
            if (!ensure_bits(c, 32)) goto need_input;
            uint32_t lenv = take_bits(c, 16);
            uint32_t nlen = take_bits(c, 16);
            if (lenv != (~nlen & 0xffffu)) goto error;
            c->stored_left = lenv;
            c->mode = INF_STORED_COPY;
            continue;
        }

        case INF_STORED_COPY: {
            while (c->stored_left > 0) {
                if (c->in_pos >= c->in_len) goto need_input;
                if (produced >= out_cap) goto need_output;
                uint8_t b = c->in[c->in_pos++];
                window_put(c, b);
                out[produced++] = b;
                c->stored_left--;
            }
            c->mode = INF_BLOCK_DONE;
            continue;
        }

        case INF_DYN_HDR: {
            if (!ensure_bits(c, 14)) goto need_input;
            c->hlit  = take_bits(c, 5) + 257;
            c->hdist = take_bits(c, 5) + 1;
            c->hclen = take_bits(c, 4) + 4;
            if (c->hlit > INFLATE_MAXLCODES || c->hdist > INFLATE_MAXDCODES) goto error;
            c->ncode = 0;
            c->mode = INF_DYN_CLLEN;
            continue;
        }

        case INF_DYN_CLLEN: {
            while (c->ncode < c->hclen) {
                if (!ensure_bits(c, 3)) goto need_input;
                c->cl_lens[CLORDER[c->ncode]] = (uint8_t)take_bits(c, 3);
                c->ncode++;
            }
            for (unsigned i = c->hclen; i < 19; i++) c->cl_lens[CLORDER[i]] = 0;
            {
                uint16_t cl16[19];
                for (int i = 0; i < 19; i++) cl16[i] = c->cl_lens[i];
                int rc = huff_build(&c->cl_table, cl16, 19);
                if (!huff_ok(rc, &c->cl_table, 19)) goto error;
            }
            c->nlens = 0;
            c->pending_cl_sym = -1;
            c->mode = INF_DYN_LENGTHS;
            continue;
        }

        case INF_DYN_LENGTHS: {
            unsigned total = c->hlit + c->hdist;
            while (c->nlens < total) {
                if (c->pending_cl_sym < 0) {
                    int sym;
                    int rc = decode_symbol(c, &c->cl_table, &sym);
                    if (rc == 0) goto need_input;
                    if (rc < 0) goto error;
                    c->pending_cl_sym = sym;
                }
                int sym = c->pending_cl_sym;
                if (sym < 16) {
                    c->lens[c->nlens++] = (uint16_t)sym;
                    c->pending_cl_sym = -1;
                } else {
                    int nb   = sym == 16 ? 2 : sym == 17 ? 3 : 7;
                    int base = sym == 16 ? 3 : sym == 17 ? 3 : 11;
                    if (!ensure_bits(c, nb)) goto need_input;
                    unsigned rep = (unsigned)base + take_bits(c, nb);
                    uint16_t fill;
                    if (sym == 16) {
                        if (c->nlens == 0) goto error;
                        fill = c->lens[c->nlens - 1];
                    } else {
                        fill = 0;
                    }
                    if (c->nlens + rep > total) goto error;
                    for (unsigned k = 0; k < rep; k++) c->lens[c->nlens++] = fill;
                    c->pending_cl_sym = -1;
                }
            }
            {
                int rcl = huff_build(&c->lit_table, c->lens, c->hlit);
                if (!huff_ok(rcl, &c->lit_table, c->hlit)) goto error;
                int rcd = huff_build(&c->dist_table, c->lens + c->hlit, c->hdist);
                if (!huff_ok(rcd, &c->dist_table, c->hdist)) goto error;
            }
            c->mode = INF_DECODE_SYM;
            continue;
        }

        case INF_DECODE_SYM: {
            int sym;
            int rc = decode_symbol(c, &c->lit_table, &sym);
            if (rc == 0) goto need_input;
            if (rc < 0) goto error;
            if (sym < 256) {
                c->copy_remaining = 1;
                c->copy_dist = 0;
                c->copy_literal = (uint8_t)sym;
                c->mode = INF_COPY;
            } else if (sym == 256) {
                c->mode = INF_BLOCK_DONE;
            } else if (sym <= 285) {
                c->len_sym = sym - 257;
                c->mode = INF_LEN_EXTRA;
            } else {
                goto error;                                /* 286/287: never valid */
            }
            continue;
        }

        case INF_LEN_EXTRA: {
            int nb = LEXT[c->len_sym];
            if (!ensure_bits(c, nb)) goto need_input;
            c->match_len = LBASE[c->len_sym] + (nb ? take_bits(c, nb) : 0);
            c->mode = INF_DECODE_DIST;
            continue;
        }

        case INF_DECODE_DIST: {
            int sym;
            int rc = decode_symbol(c, &c->dist_table, &sym);
            if (rc == 0) goto need_input;
            if (rc < 0) goto error;
            if (sym > 29) goto error;                       /* 30/31: never valid */
            c->dist_sym = sym;
            c->mode = INF_DIST_EXTRA;
            continue;
        }

        case INF_DIST_EXTRA: {
            int nb = DEXT[c->dist_sym];
            if (!ensure_bits(c, nb)) goto need_input;
            c->match_dist = DBASE[c->dist_sym] + (nb ? take_bits(c, nb) : 0);
            if (c->match_dist > c->window_filled) goto error;  /* points before stream start */
            c->copy_remaining = c->match_len;
            c->copy_dist = c->match_dist;
            c->mode = INF_COPY;
            continue;
        }

        case INF_COPY: {
            while (c->copy_remaining > 0) {
                if (produced >= out_cap) goto need_output;
                uint8_t b = c->copy_dist == 0
                          ? c->copy_literal
                          : c->window[(c->window_pos + INFLATE_WINDOW - c->copy_dist) % INFLATE_WINDOW];
                window_put(c, b);
                out[produced++] = b;
                c->copy_remaining--;
            }
            c->mode = INF_DECODE_SYM;
            continue;
        }

        case INF_BLOCK_DONE: {
            if (c->final_block) { c->mode = INF_DONE; goto stream_done; }
            c->mode = INF_BLOCK_HDR;
            continue;
        }

        default:
            goto error;
        }
    }

need_input:
    *in_used = c->in_pos; *out_len = produced; *done = 0;
    return 0;
need_output:
    *in_used = c->in_pos; *out_len = produced; *done = 0;
    return 0;
stream_done:
    *in_used = c->in_pos; *out_len = produced; *done = 1;
    return 0;
error:
    c->mode = INF_ERROR;
    *in_used = c->in_pos; *out_len = produced; *done = 0;
    return -1;
}
