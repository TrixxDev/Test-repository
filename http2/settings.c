/* HTTP/2 SETTINGS frame — see settings.h. */
#include "settings.h"

int h2_build_settings_empty(uint8_t *out, size_t cap)
{
    h2_frame_header h = { 0, H2_TYPE_SETTINGS, 0, 0 };
    return h2_write_frame_header(out, cap, &h);
}

int h2_build_settings_ack(uint8_t *out, size_t cap)
{
    h2_frame_header h = { 0, H2_TYPE_SETTINGS, H2_FLAG_ACK, 0 };
    return h2_write_frame_header(out, cap, &h);
}
