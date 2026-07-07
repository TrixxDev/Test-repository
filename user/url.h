/* user/url.h — absolute-URL parsing and RFC 3986 §5.3 reference resolution, for
 * following HTTP redirects (Phase 15.2).
 *
 * Freestanding, like x509/ and tls/: only <stddef.h>, no libc, no allocation, so
 * the exact same object links into user/httpsget and a host test binary. */
#pragma once
#include <stddef.h>

#define URL_HOST_MAX 128
#define URL_PATH_MAX 512    /* "/path?query", always present and '/'-prefixed */

struct url {
    int  https;             /* 0 = http, 1 = https */
    char host[URL_HOST_MAX];
    int  port;
    char path[URL_PATH_MAX];
};

/* Parse an absolute URL "http(s)://host[:port][/path][?query][#frag]". Any
 * fragment is dropped (HTTP never sends it on the wire). Returns 0 on success,
 * -1 if `s` isn't a well-formed absolute http(s) URL. */
int url_parse(const char *s, int len, struct url *out);

/* Resolve a Location: header value (`loc`) seen in a response to `base`,
 * producing the next request target. Handles, per RFC 3986 §5.3: an absolute
 * URI, a network-path reference ("//host/path"), an absolute-path reference
 * ("/path"), a query-only reference ("?q=1"), and a relative-path reference
 * ("next" or "../next"), including "." / ".." segment removal (§5.2.4). A
 * fragment on `loc` is dropped. Returns 0 on success, -1 if unresolvable. */
int url_resolve(const struct url *base, const char *loc, int loclen, struct url *out);
