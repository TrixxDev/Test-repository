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
