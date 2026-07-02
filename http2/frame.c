/* HTTP/2 frame header — see frame.h. */
#include "frame.h"

int h2_write_frame_header(uint8_t *out, size_t cap, const h2_frame_header *h)
{
    if (cap < H2_FRAME_HEADER_LEN) return -1;
    if (h->length > 0xFFFFFFu) return -1;
    if (h->stream_id > 0x7FFFFFFFu) return -1;
    out[0] = (uint8_t)(h->length >> 16);
    out[1] = (uint8_t)(h->length >> 8);
    out[2] = (uint8_t)(h->length);
    out[3] = h->type;
    out[4] = h->flags;
    out[5] = (uint8_t)((h->stream_id >> 24) & 0x7Fu);   /* top bit reserved, forced 0 */
    out[6] = (uint8_t)(h->stream_id >> 16);
    out[7] = (uint8_t)(h->stream_id >> 8);
    out[8] = (uint8_t)(h->stream_id);
    return H2_FRAME_HEADER_LEN;
}

int h2_parse_frame_header(const uint8_t *in, size_t len, h2_frame_header *out)
{
    if (len < H2_FRAME_HEADER_LEN) return -1;
    out->length = ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | (uint32_t)in[2];
    out->type = in[3];
    out->flags = in[4];
    out->stream_id = (((uint32_t)in[5] & 0x7Fu) << 24) | ((uint32_t)in[6] << 16) |
                     ((uint32_t)in[7] << 8) | (uint32_t)in[8];
    return H2_FRAME_HEADER_LEN;
}

/* ------------------------------------------------------------------ */
/* Generic incremental frame reader (Phase 17.1.2)                    */
/* ------------------------------------------------------------------ */

void h2_frame_reader_init(h2_frame_reader *r)
{
    r->len = 0;
    r->need = H2_FRAME_HEADER_LEN;
}

int h2_frame_reader_feed(h2_frame_reader *r, const uint8_t *data, size_t len)
{
    size_t pos = 0;
    while (pos < len && r->len < r->need) {
        size_t want = r->need - r->len;
        size_t have = len - pos;
        size_t take = want < have ? want : have;
        for (size_t i = 0; i < take; i++) r->buf[r->len + i] = data[pos + i];
        r->len += take;
        pos += take;

        if (r->len == H2_FRAME_HEADER_LEN && r->need == H2_FRAME_HEADER_LEN) {
            /* the header itself just completed -- now we know the real
             * target: header + however much payload this frame declares */
            h2_frame_header h;
            h2_parse_frame_header(r->buf, H2_FRAME_HEADER_LEN, &h);
            if (h.length > H2_FRAME_PAYLOAD_MAX) return -1;
            r->need = H2_FRAME_HEADER_LEN + h.length;
            continue;   /* keep consuming into the payload within this same call, if there's more */
        }
    }
    return (int)pos;
}

int h2_frame_reader_next(h2_frame_reader *r, h2_frame_header *out,
                         const uint8_t **payload, size_t *payload_len)
{
    if (r->len < r->need) return 0;   /* header, or header+payload, still incomplete */
    h2_parse_frame_header(r->buf, H2_FRAME_HEADER_LEN, out);
    if (payload) *payload = r->buf + H2_FRAME_HEADER_LEN;
    if (payload_len) *payload_len = r->need - H2_FRAME_HEADER_LEN;
    r->len = 0;
    r->need = H2_FRAME_HEADER_LEN;
    return 1;
}
