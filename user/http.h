/* Minimal HTTP/1.x response parser (userspace).
 *
 * Turns the raw bytes returned by http_get() into a structured object: status
 * code, a few interesting headers, and where the body begins. Deliberately small
 * -- no chunked transfer-encoding, no header folding -- but enough for Aurora
 * Fetch to show a real result and, later, to follow redirects. */
#pragma once

struct http_response {
    int  status;            /* status code (e.g. 200, 404); 0 if unparsable   */
    int  content_length;    /* Content-Length, or -1 if the header is absent   */
    int  header_len;        /* bytes of status line + headers + the blank line */
    char content_type[64];
    char server[64];
    char location[256];     /* Location: (for redirects)                       */
};

/* Parse `len` bytes of an HTTP response into *out. Returns 0 on success (it
 * looked like HTTP and `status` is set), -1 otherwise. */
int http_parse(const char *buf, int len, struct http_response *out);
