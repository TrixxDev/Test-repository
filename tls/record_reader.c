/* TLS record framing over a byte stream — see record_reader.h. */
#include "record_reader.h"

void tls_reader_init(tls_record_reader *r)
{
    r->start = 0;
    r->len = 0;
    r->error = 0;
}

int tls_reader_feed(tls_record_reader *r, const uint8_t *data, size_t len)
{
    /* compact: slide unconsumed bytes to the front (forward copy, dst < src) */
    if (r->start > 0) {
        size_t n = r->len - r->start;
        for (size_t i = 0; i < n; i++) r->buf[i] = r->buf[r->start + i];
        r->len = n;
        r->start = 0;
    }
    if (r->len + len > sizeof r->buf) return -1;        /* would overflow: drain first */
    for (size_t i = 0; i < len; i++) r->buf[r->len + i] = data[i];
    r->len += len;
    return 0;
}

int tls_reader_next(tls_record_reader *r, const uint8_t **rec, size_t *reclen)
{
    if (r->error) return -1;

    size_t avail = r->len - r->start;
    if (avail < TLS_RECORD_HEADER_LEN) return 0;        /* header not complete yet */

    const uint8_t *h = r->buf + r->start;
    size_t body = ((size_t)h[3] << 8) | h[4];
    if (body > TLS_RECORD_MAX_BODY) { r->error = 1; return -1; }   /* malformed length */

    size_t total = TLS_RECORD_HEADER_LEN + body;
    if (avail < total) return 0;                        /* body not complete yet */

    *rec = h;
    *reclen = total;
    r->start += total;
    return 1;
}
