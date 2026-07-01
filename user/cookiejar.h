/* user/cookiejar.h — a compact HTTP cookie jar (RFC 6265), for `httpsget`
 * (Phase 15.9).
 *
 * Freestanding, like url.c and x509/: only <stddef.h>/<stdint.h>, no libc,
 * no allocation, so the exact same object links into user/httpsget and a
 * host test binary.
 *
 * Deliberately compact: a fixed-size array with LRU eviction, Domain, Path,
 * Expires/Max-Age, Secure and HttpOnly. SameSite, Priority, Partitioned and
 * other newer attributes are parsed as "unknown" and silently ignored --
 * not load-bearing for a plain HTTPS client. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define COOKIE_JAR_N      32
#define COOKIE_NAME_MAX   48
#define COOKIE_VALUE_MAX  192
#define COOKIE_DOMAIN_MAX 64
#define COOKIE_PATH_MAX   128

typedef struct {
    int      valid;
    char     name[COOKIE_NAME_MAX];
    char     value[COOKIE_VALUE_MAX];
    char     domain[COOKIE_DOMAIN_MAX];   /* normalized: lowercase, no leading dot */
    char     path[COOKIE_PATH_MAX];
    uint64_t expires_at;   /* Unix seconds; 0 = session cookie (no expiry) */
    int      secure;       /* only sent over https */
    int      http_only;    /* stored for completeness; httpsget has no script layer to guard */
    int      host_only;    /* Domain attribute was absent -> exact host match only */
    uint64_t last_used;    /* LRU clock value (see cookie_jar.clock), not wall time */
} cookie_entry;

typedef struct {
    cookie_entry entries[COOKIE_JAR_N];
    uint64_t     clock;    /* incremented on every touch, for LRU eviction */
} cookie_jar;

void cookie_jar_init(cookie_jar *jar);

/* Parse and apply one Set-Cookie header VALUE (the bytes after "Set-Cookie:",
 * not including the header name) received in response to a request for
 * `request_host`/`request_path` over http(s) (`request_is_https`, currently
 * unused by the set path -- Secure only gates *sending*, per RFC 6265 -- but
 * taken for symmetry with cookie_jar_build_header and future use). Absent
 * Domain/Path attributes default per RFC 6265 SS5.1.3/SS5.1.4 (host-only exact
 * match; the "default-path" derived from request_path). An explicit Domain
 * attribute that the request host doesn't domain-match is rejected (the
 * whole cookie is ignored) -- a server may not set cookies for domains it
 * doesn't control. An effective expiry at or before `now` deletes any
 * existing same-(name,domain,path) entry instead of storing a new one
 * (RFC 6265 SS5.3) -- this is how a server asks a client to forget a cookie.
 * `now` is Unix seconds. Malformed input (no "=" in the cookie-pair, an
 * oversized name) is silently ignored, matching a real user agent. */
void cookie_jar_set(cookie_jar *jar, const char *v, int vlen,
                    const char *request_host, const char *request_path,
                    int request_is_https, uint64_t now);

/* Build "name1=value1; name2=value2" from every unexpired entry that
 * domain-matches `host`, path-matches `path`, and (if Secure) `is_https`.
 * Writes into `out` (capacity `outcap`; NOT null-terminated, matching the
 * rest of httpsget's header-building code) and returns the length written
 * (0 if nothing matched -- the caller should omit the Cookie header
 * entirely, not send an empty one). Touches (LRU) every cookie it includes,
 * and lazily evicts any expired entry it happens to walk past. */
int cookie_jar_build_header(cookie_jar *jar, const char *host, const char *path,
                            int is_https, uint64_t now, char *out, int outcap);
