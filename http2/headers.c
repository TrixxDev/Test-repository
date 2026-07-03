/* HTTP/2 HEADERS frame — see headers.h. */
#include "headers.h"
#include "hpack.h"

static int eq_lit(const char *s, size_t len, const char *lit)
{
    size_t i = 0;
    for (; lit[i]; i++) if (i >= len || s[i] != lit[i]) return 0;
    return i == len;
}

/* Decimal ASCII text for `v` into `out` (no leading zeros, "0" for zero).
 * Freestanding -- no snprintf/itoa in this directory's convention. */
static size_t put_udec(char *out, size_t v)
{
    if (v == 0) { out[0] = '0'; return 1; }
    char tmp[20]; size_t tn = 0;
    while (v > 0) { tmp[tn++] = (char)('0' + v % 10); v /= 10; }
    for (size_t i = 0; i < tn; i++) out[i] = tmp[tn - 1 - i];
    return tn;
}

int h2_build_headers(uint8_t *out, size_t cap, uint32_t stream_id,
                     const char *method, size_t method_len,
                     const char *authority, size_t authority_len,
                     const char *path, size_t path_len,
                     const char *user_agent, size_t user_agent_len,
                     const char *content_type, size_t content_type_len,
                     size_t body_len)
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

    /* Content-Type/Content-Length (Phase 17.4.1) -- only when a body
     * follows. Content-Length is always derived from `body_len` itself,
     * the same way build_request()'s own HTTP/1.1 Content-Length always is
     * -- never a separately-passed value that could drift from the DATA
     * frame(s) the caller actually sends. */
    if (body_len > 0) {
        if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_CONTENT_TYPE, content_type, content_type_len) != 0) return -1;
        char lenbuf[20];
        size_t lenlen = put_udec(lenbuf, body_len);
        if (hpack_put_literal_indexed_name(out, cap, &pos, HPACK_IDX_CONTENT_LENGTH, lenbuf, lenlen) != 0) return -1;
    }

    size_t payload_len = pos - H2_FRAME_HEADER_LEN;
    uint8_t flags = H2_FLAG_END_HEADERS | (body_len == 0 ? H2_FLAG_END_STREAM : 0);
    h2_frame_header h = { (uint32_t)payload_len, H2_TYPE_HEADERS, flags, stream_id };
    if (h2_write_frame_header(out, cap, &h) < 0) return -1;
    return (int)pos;
}
