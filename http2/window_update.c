/* HTTP/2 WINDOW_UPDATE frame — see window_update.h. */
#include "window_update.h"

int h2_window_update_parse(const uint8_t *payload, size_t payload_len, uint32_t *increment)
{
    if (payload_len != 4) return -1;
    uint32_t v = ((uint32_t)(payload[0] & 0x7Fu) << 24) | ((uint32_t)payload[1] << 16) |
                 ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
    if (v == 0) return -1;
    *increment = v;
    return 0;
}

int h2_window_update_build(uint8_t *out, size_t cap, uint32_t stream_id, uint32_t increment)
{
    if (increment == 0 || increment > 0x7FFFFFFFu) return -1;
    if (cap < (size_t)H2_FRAME_HEADER_LEN + 4) return -1;

    h2_frame_header h = { 4, H2_TYPE_WINDOW_UPDATE, 0, stream_id };
    int hn = h2_write_frame_header(out, cap, &h);
    if (hn < 0) return -1;

    out[hn]     = (uint8_t)((increment >> 24) & 0x7Fu);
    out[hn + 1] = (uint8_t)(increment >> 16);
    out[hn + 2] = (uint8_t)(increment >> 8);
    out[hn + 3] = (uint8_t)increment;
    return hn + 4;
}
