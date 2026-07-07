/* gzip container (RFC 1952) -- see gzip.h. */
#include "gzip.h"

#define FLG_FTEXT    0x01
#define FLG_FHCRC    0x02
#define FLG_FEXTRA   0x04
#define FLG_FNAME    0x08
#define FLG_FCOMMENT 0x10
#define FLG_RESERVED 0xe0

void gzip_init(gzip_ctx *g)
{
    g->mode = GZ_HDR_FIXED;
    g->hdrpos = 0;
    g->xlen = 0; g->xlen_read = 0; g->xlen_left = 0;
    g->fhcrc_left = 0;
    g->trailer_pos = 0;
    g->total_out = 0;
    inflate_init(&g->inf);
    crc32_init(&g->crc);
}

/* After the fixed header (or FEXTRA/FNAME/FCOMMENT, in that order) is done,
 * the next optional field to expect -- or the body if none remain. */
static gzip_mode next_after(uint8_t flg, gzip_mode from)
{
    if (from <= GZ_HDR_FEXTRA_SKIP && (flg & FLG_FNAME))    return GZ_HDR_FNAME;
    if (from <= GZ_HDR_FNAME       && (flg & FLG_FCOMMENT)) return GZ_HDR_FCOMMENT;
    if (from <= GZ_HDR_FCOMMENT    && (flg & FLG_FHCRC))    return GZ_HDR_FHCRC;
    return GZ_BODY;
}

int gzip_feed(gzip_ctx *g, const uint8_t *in, size_t in_len,
             uint8_t *out, size_t out_cap,
             size_t *in_used, size_t *out_len, int *done)
{
    size_t pos = 0;
    size_t produced = 0;

    if (g->mode == GZ_DONE)  { *in_used = 0; *out_len = 0; *done = 1; return 0; }
    if (g->mode == GZ_ERROR) { *in_used = 0; *out_len = 0; *done = 0; return -1; }

    for (;;) {
        switch (g->mode) {

        case GZ_HDR_FIXED: {
            while (g->hdrpos < 10) {
                if (pos >= in_len) goto need_input;
                g->hdrbuf[g->hdrpos++] = in[pos++];
            }
            if (g->hdrbuf[0] != 0x1f || g->hdrbuf[1] != 0x8b || g->hdrbuf[2] != 8) goto error;
            g->flg = g->hdrbuf[3];
            if (g->flg & FLG_RESERVED) goto error;
            g->mode = (g->flg & FLG_FEXTRA) ? GZ_HDR_FEXTRA_LEN : next_after(g->flg, GZ_HDR_FEXTRA_SKIP);
            continue;
        }

        case GZ_HDR_FEXTRA_LEN: {
            while (g->xlen_read < 2) {
                if (pos >= in_len) goto need_input;
                g->xlen |= (unsigned)in[pos++] << (8 * g->xlen_read);
                g->xlen_read++;
            }
            g->xlen_left = g->xlen;
            g->mode = GZ_HDR_FEXTRA_SKIP;
            continue;
        }

        case GZ_HDR_FEXTRA_SKIP: {
            while (g->xlen_left > 0) {
                if (pos >= in_len) goto need_input;
                pos++; g->xlen_left--;
            }
            g->mode = next_after(g->flg, GZ_HDR_FEXTRA_SKIP);
            continue;
        }

        case GZ_HDR_FNAME: {
            int found = 0;
            while (pos < in_len) { if (in[pos++] == 0) { found = 1; break; } }
            if (!found) goto need_input;
            g->mode = next_after(g->flg, GZ_HDR_FNAME);
            continue;
        }

        case GZ_HDR_FCOMMENT: {
            int found = 0;
            while (pos < in_len) { if (in[pos++] == 0) { found = 1; break; } }
            if (!found) goto need_input;
            g->mode = next_after(g->flg, GZ_HDR_FCOMMENT);
            continue;
        }

        case GZ_HDR_FHCRC: {
            if (g->fhcrc_left == 0) g->fhcrc_left = 2;
            while (g->fhcrc_left > 0) {
                if (pos >= in_len) goto need_input;
                pos++; g->fhcrc_left--;              /* not verified -- see gzip.h */
            }
            g->mode = GZ_BODY;
            continue;
        }

        case GZ_BODY: {
            size_t in_used_i, out_len_i; int done_i;
            int rc = inflate_feed(&g->inf, in + pos, in_len - pos, out + produced, out_cap - produced,
                                  &in_used_i, &out_len_i, &done_i);
            pos += in_used_i;
            if (out_len_i > 0) {
                crc32_update(&g->crc, out + produced, out_len_i);
                g->total_out += (uint32_t)out_len_i;
                produced += out_len_i;
            }
            if (rc != 0) goto error;
            if (done_i) { g->mode = GZ_TRAILER; continue; }
            if (produced >= out_cap) goto need_output;
            goto need_input;
        }

        case GZ_TRAILER: {
            while (g->trailer_pos < 8) {
                if (pos >= in_len) goto need_input;
                g->trailer[g->trailer_pos++] = in[pos++];
            }
            {
                uint32_t want_crc = (uint32_t)g->trailer[0] | ((uint32_t)g->trailer[1] << 8) |
                                   ((uint32_t)g->trailer[2] << 16) | ((uint32_t)g->trailer[3] << 24);
                uint32_t want_isize = (uint32_t)g->trailer[4] | ((uint32_t)g->trailer[5] << 8) |
                                      ((uint32_t)g->trailer[6] << 16) | ((uint32_t)g->trailer[7] << 24);
                if (want_crc != crc32_final(&g->crc)) goto error;
                if (want_isize != g->total_out) goto error;
            }
            g->mode = GZ_DONE;
            goto stream_done;
        }

        default:
            goto error;
        }
    }

need_input:
    *in_used = pos; *out_len = produced; *done = 0;
    return 0;
need_output:
    *in_used = pos; *out_len = produced; *done = 0;
    return 0;
stream_done:
    *in_used = pos; *out_len = produced; *done = 1;
    return 0;
error:
    g->mode = GZ_ERROR;
    *in_used = pos; *out_len = produced; *done = 0;
    return -1;
}
