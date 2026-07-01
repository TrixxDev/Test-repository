/* HTTP/1.x response parser + a tiny GET client over the INET socket API.
 * See user/http.h. */
#include "http.h"
#include "libc.h"

int http_get(const char *host, void *buf, int cap)
{
    int s = inet_socket();
    if (s < 0)
        return -1;
    int r = inet_connect(s, host, 80);
    if (r != 0) {                               /* -2 DNS, -3 connect */
        close(s);
        return r;
    }

    /* "GET / HTTP/1.0\r\nHost: <host>\r\nConnection: close\r\n\r\n" */
    char req[200]; int n = 0;
    const char *a = "GET / HTTP/1.0\r\nHost: ";
    for (int i = 0; a[i]; i++) req[n++] = a[i];
    for (int i = 0; host[i] && n < 170; i++) req[n++] = host[i];
    const char *b = "\r\nConnection: close\r\n\r\n";
    for (int i = 0; b[i]; i++) req[n++] = b[i];
    if (write(s, req, n) < 0) { close(s); return -3; }

    char *out = (char *)buf;
    int total = 0;
    while (total < cap) {
        int g = read(s, out + total, cap - total);   /* blocks; 0 = EOF (peer closed) */
        if (g <= 0)
            break;
        total += g;
    }
    close(s);
    return total;
}

/* Case-insensitive test: does `s` begin with `prefix`? */
static int ci_starts(const char *s, int slen, const char *prefix)
{
    for (int i = 0; prefix[i]; i++) {
        if (i >= slen) return 0;
        char a = s[i], b = prefix[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static void copy_field(char *dst, int cap, const char *src, int len)
{
    int n = len < cap - 1 ? len : cap - 1;
    for (int i = 0; i < n; i++) dst[i] = src[i];
    dst[n] = '\0';
}

/* Case-insensitive: does `hay[0..haylen)` contain `needle` anywhere? Good
 * enough for header values like "keep-alive" or "close" (possibly alongside
 * other tokens, e.g. "close, Upgrade") without full RFC 7230 tokenizing. */
static int ci_contains(const char *hay, int haylen, const char *needle)
{
    int nlen = 0; while (needle[nlen]) nlen++;
    for (int j = 0; j + nlen <= haylen; j++)
        if (ci_starts(hay + j, haylen - j, needle)) return 1;
    return 0;
}

int http_parse(const char *buf, int len, struct http_response *out)
{
    memset(out, 0, sizeof(*out));
    out->content_length = -1;
    out->header_len = len;

    if (len < 12 || !ci_starts(buf, len, "http/1."))
        return -1;
    out->http_minor = (buf[7] == '1') ? 1 : 0;    /* "HTTP/1.0" vs "HTTP/1.1" */

    /* Status code: after "HTTP/1.x " comes a 3-digit code. */
    int i = 0;
    while (i < len && buf[i] != ' ') i++;
    while (i < len && buf[i] == ' ') i++;
    int code = 0;
    while (i < len && buf[i] >= '0' && buf[i] <= '9') { code = code * 10 + (buf[i] - '0'); i++; }
    out->status = code;

    /* Walk the header lines until the blank line that ends the header block. */
    int conn_close = 0, conn_keepalive = 0;
    int p = 0;
    while (p < len && buf[p] != '\n') p++;       /* skip the status line */
    p++;
    while (p < len) {
        int e = p;
        while (e < len && buf[e] != '\n') e++;   /* e = end of line ('\n' or len) */
        int end = e;
        if (end > p && buf[end - 1] == '\r') end--;   /* strip CR */

        if (end == p) {                          /* blank line: headers done */
            out->header_len = (e < len) ? e + 1 : len;
            break;
        }

        int linelen = end - p;
        int c = p;
        while (c < end && buf[c] != ':') c++;
        if (c < end) {
            int v = c + 1;
            while (v < end && buf[v] == ' ') v++;
            int vlen = end - v;
            if (ci_starts(buf + p, linelen, "content-length:")) {
                int nlen = 0;
                for (int k = v; k < end && buf[k] >= '0' && buf[k] <= '9'; k++)
                    nlen = nlen * 10 + (buf[k] - '0');
                out->content_length = nlen;
            } else if (ci_starts(buf + p, linelen, "content-type:")) {
                copy_field(out->content_type, sizeof(out->content_type), buf + v, vlen);
            } else if (ci_starts(buf + p, linelen, "server:")) {
                copy_field(out->server, sizeof(out->server), buf + v, vlen);
            } else if (ci_starts(buf + p, linelen, "location:")) {
                copy_field(out->location, sizeof(out->location), buf + v, vlen);
            } else if (ci_starts(buf + p, linelen, "connection:")) {
                if (ci_contains(buf + v, vlen, "close")) conn_close = 1;
                if (ci_contains(buf + v, vlen, "keep-alive")) conn_keepalive = 1;
            } else if (ci_starts(buf + p, linelen, "transfer-encoding:")) {
                if (ci_contains(buf + v, vlen, "chunked")) out->chunked = 1;
            }
        }
        p = (e < len) ? e + 1 : len;
    }

    /* Phase 15.4: may this connection be reused for another request? HTTP/1.1
     * defaults to keep-alive unless "Connection: close" says otherwise;
     * HTTP/1.0 defaults to close unless "Connection: keep-alive" opts in. A
     * chunked or length-less body has no way to know where it ends short of
     * the connection closing, so it can never be reused regardless of what
     * Connection: says. */
    int wants_keepalive = conn_close ? 0 : (conn_keepalive || out->http_minor == 1);
    out->keep_alive = wants_keepalive && out->content_length >= 0 && !out->chunked;

    return 0;
}
