/* Minimal HTTP/1.x response parser (userspace).
 *
 * Turns the raw bytes returned by http_get() into a structured object: status
 * code, a few interesting headers, and where the body begins. Deliberately small
 * -- no header folding -- but enough for Aurora Fetch to show a real result,
 * httpsget to follow redirects, and (Phase 15.4) to decide whether a connection
 * may be reused for a second request. */
#pragma once

struct http_response {
    int  status;            /* status code (e.g. 200, 404); 0 if unparsable   */
    int  content_length;    /* Content-Length, or -1 if the header is absent   */
    int  header_len;        /* bytes of status line + headers + the blank line */
    int  http_minor;        /* 0 = HTTP/1.0, 1 = HTTP/1.1 (or unrecognized -> 0) */
    int  chunked;            /* Transfer-Encoding: chunked present              */
    int  keep_alive;        /* connection may be reused for another request:
                              * wants keep-alive (HTTP/1.1 default, or an
                              * explicit "Connection: keep-alive"; never if
                              * "Connection: close" is present) AND the response
                              * has a determinate length (Content-Length) -- a
                              * chunked or length-less body needs the connection
                              * closed to know where it ends, so it never
                              * qualifies here even if the server said keep-alive */
    char content_type[64];
    char server[64];
    char location[256];     /* Location: (for redirects)                       */
};

/* Parse `len` bytes of an HTTP response into *out. Returns 0 on success (it
 * looked like HTTP and `status` is set), -1 otherwise. */
int http_parse(const char *buf, int len, struct http_response *out);

/* Fetch "/" from host:80 over HTTP/1.0 into buf, using the INET socket API
 * (socket -> connect -> send -> recv -> close), entirely in user space. Returns
 * bytes received, or <0 (-1 socket, -2 DNS fail, -3 connect fail). */
int http_get(const char *host, void *buf, int cap);
