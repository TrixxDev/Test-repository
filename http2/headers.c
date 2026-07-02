/* HTTP/2 HEADERS frame — see headers.h. */
#include "headers.h"
#include "hpack.h"

static int eq_lit(const char *s, size_t len, const char *lit)
{
    size_t i = 0;
    for (; lit[i]; i++) if (i >= len || s[i] != lit[i]) return 0;
    return i == len;
}

int h2_build_headers(uint8_t *out, size_t cap, uint32_t stream_id,
                     const char *method, size_t method_len,
                     const char *authority, size_t authority_len,
                     const char *path, size_t path_len,
                     const char *user_agent, size_t user_agent_len)
{
    if (cap < H2_FRAME_HEADER_LEN) return -1;
    size_t pos = H2_FRAME_HEADER_LEN;   /* room for the frame header, filled in at the end */

    /* :method -- indexed when it's one of the two the static table has a
     * value for, otherwise a literal using GET's entry for the name only. */
    if (eq_lit(method, method_len, "GET")) {
        if (hpack_put_indexed(out, cap, &pos, HPACK_IDX_METHOD_GET) != 0) return -1;
    } else if (eq_lit(method, method_len, "POST")) {
        if (hpack_put_indexed(out, cap, &pos, HPACK_IDX_METHOD_POST) != 0) return -1;
    } else {
        if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_METHOD_GET, method, method_len) != 0) return -1;
    }

    /* :scheme -- always "https"; this client only ever reaches h2 over TLS
     * (ALPN, Phase 17.0, is only ever offered inside fetch_begin()'s
     * u->https branch), so there's nothing to parameterize here. */
    if (hpack_put_indexed(out, cap, &pos, HPACK_IDX_SCHEME_HTTPS) != 0) return -1;

    /* :authority -- always a literal; nothing in the static table has a
     * fixed value for this by definition (every real host differs). */
    if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_AUTHORITY, authority, authority_len) != 0) return -1;

    /* :path -- indexed only for the exact root path, literal otherwise. */
    if (eq_lit(path, path_len, "/")) {
        if (hpack_put_indexed(out, cap, &pos, HPACK_IDX_PATH_ROOT) != 0) return -1;
    } else {
        if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_PATH_ROOT, path, path_len) != 0) return -1;
    }

    /* user-agent -- optional, always a literal (the static table only has
     * the name, no value). */
    if (user_agent) {
        if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_USER_AGENT, user_agent, user_agent_len) != 0) return -1;
    }

    size_t payload_len = pos - H2_FRAME_HEADER_LEN;
    h2_frame_header h = { (uint32_t)payload_len, H2_TYPE_HEADERS,
                          (uint8_t)(H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM), stream_id };
    if (h2_write_frame_header(out, cap, &h) < 0) return -1;
    return (int)pos;
}
