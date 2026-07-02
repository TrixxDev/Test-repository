/* HTTP/2 DATA frame — see data.h. */
#include "data.h"

int h2_data_parse(const uint8_t *payload, size_t payload_len, uint8_t flags,
                  const uint8_t **data, size_t *data_len)
{
    if (!(flags & H2_FLAG_PADDED)) {
        *data = payload;
        *data_len = payload_len;
        return 0;
    }
    if (payload_len < 1) return -1;
    uint8_t padlen = payload[0];
    if ((size_t)padlen + 1 > payload_len) return -1;   /* padding >= the whole payload */
    *data = payload + 1;
    *data_len = payload_len - 1 - (size_t)padlen;
    return 0;
}

int h2_data_build(uint8_t *out, size_t cap, uint32_t stream_id,
                  const uint8_t *data, size_t data_len, int end_stream)
{
    h2_frame_header h = { (uint32_t)data_len, H2_TYPE_DATA,
                          (uint8_t)(end_stream ? H2_FLAG_END_STREAM : 0), stream_id };
    int hn = h2_write_frame_header(out, cap, &h);
    if (hn < 0) return -1;
    if (cap - (size_t)hn < data_len) return -1;
    for (size_t i = 0; i < data_len; i++) out[(size_t)hn + i] = data[i];
    return hn + (int)data_len;
}
