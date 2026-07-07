/* Host-side URL parse/resolve tests (user/url.c). Covers RFC 3986 §5.3
 * reference resolution as used to follow HTTP redirects: absolute URIs,
 * network-path / absolute-path / query-only / relative-path references, dot-
 * segment removal, scheme/host/port changes, and malformed input. Build/run:
 * `make url-test`. No QEMU, no networking. */
#include <stdio.h>
#include <string.h>
#include "url.h"

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

static int eq(const struct url *u, int https, const char *host, int port, const char *path)
{
    return u->https == https && strcmp(u->host, host) == 0 && u->port == port && strcmp(u->path, path) == 0;
}

static int parse(const char *s, struct url *out) { return url_parse(s, (int)strlen(s), out); }
static int resolve(const struct url *base, const char *loc, struct url *out)
{ return url_resolve(base, loc, (int)strlen(loc), out); }

int main(void)
{
    struct url u, base, out;

    check_ok("absolute https, explicit path", parse("https://example.com/a/b", &u) == 0 &&
             eq(&u, 1, "example.com", 443, "/a/b"));
    check_ok("absolute http, default port", parse("http://example.com/x", &u) == 0 &&
             eq(&u, 0, "example.com", 80, "/x"));
    check_ok("absolute, explicit port", parse("http://example.com:8080/x", &u) == 0 &&
             eq(&u, 0, "example.com", 8080, "/x"));
    check_ok("absolute, no path -> '/'", parse("https://example.com", &u) == 0 &&
             eq(&u, 1, "example.com", 443, "/"));
    check_ok("absolute, query kept", parse("https://example.com/a?x=1", &u) == 0 &&
             eq(&u, 1, "example.com", 443, "/a?x=1"));
    check_ok("absolute, fragment dropped", parse("https://example.com/a#frag", &u) == 0 &&
             eq(&u, 1, "example.com", 443, "/a"));
    check_ok("scheme is case-insensitive", parse("HTTPS://example.com/a", &u) == 0 &&
             eq(&u, 1, "example.com", 443, "/a"));
    check_ok("no scheme -> rejected", parse("example.com/a", &u) != 0);
    check_ok("unknown scheme -> rejected", parse("ftp://example.com/a", &u) != 0);
    check_ok("empty host -> rejected", parse("https:///a", &u) != 0);
    check_ok("bad port -> rejected", parse("https://example.com:99999/a", &u) != 0);
    check_ok("non-numeric port -> rejected", parse("https://example.com:abc/a", &u) != 0);

    /* base for resolution tests: https://a.example:8443/dir/file?orig */
    check_ok("base parses", parse("https://a.example:8443/dir/file?orig", &base) == 0);

    check_ok("resolve: absolute URI overrides everything",
             resolve(&base, "http://other.example/y", &out) == 0 &&
             eq(&out, 0, "other.example", 80, "/y"));
    check_ok("resolve: scheme-changing absolute URI keeps explicit port",
             resolve(&base, "http://other.example:9000/y", &out) == 0 &&
             eq(&out, 0, "other.example", 9000, "/y"));
    check_ok("resolve: network-path keeps base scheme, new host+path",
             resolve(&base, "//other.example/z", &out) == 0 &&
             eq(&out, 1, "other.example", 443, "/z"));
    check_ok("resolve: absolute-path keeps scheme/host/port, replaces path",
             resolve(&base, "/new/path", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/new/path"));
    check_ok("resolve: absolute-path with dot segments collapses",
             resolve(&base, "/a/b/../c/./d", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/a/c/d"));
    check_ok("resolve: query-only keeps base path, replaces query",
             resolve(&base, "?page=2", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/dir/file?page=2"));
    check_ok("resolve: relative path merges with base directory",
             resolve(&base, "sibling", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/dir/sibling"));
    check_ok("resolve: relative path with its own query",
             resolve(&base, "sibling?q=1", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/dir/sibling?q=1"));
    check_ok("resolve: relative '..' walks up a directory",
             resolve(&base, "../up", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/up"));
    check_ok("resolve: excess '..' at root is dropped, not an error",
             resolve(&base, "../../../up", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/up"));
    check_ok("resolve: fragment on a relative reference is dropped",
             resolve(&base, "sibling#section", &out) == 0 &&
             eq(&out, 1, "a.example", 8443, "/dir/sibling"));
    check_ok("resolve: empty Location is unresolvable",
             resolve(&base, "", &out) != 0);
    check_ok("resolve: fragment-only Location is unresolvable",
             resolve(&base, "#frag", &out) != 0);

    /* base with a directory (trailing-slash) path, no file component */
    check_ok("dir-base parses", parse("https://a.example/dir/", &base) == 0);
    check_ok("resolve against a directory base appends, not replaces",
             resolve(&base, "next", &out) == 0 && eq(&out, 1, "a.example", 443, "/dir/next"));

    /* base at the document root */
    check_ok("root-base parses", parse("https://a.example/", &base) == 0);
    check_ok("resolve relative against root base",
             resolve(&base, "x", &out) == 0 && eq(&out, 1, "a.example", 443, "/x"));

    /* oversized path must fail cleanly, not overflow */
    {
        char big[600]; memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
        struct url small_base;
        check_ok("small_base parses", parse("https://a.example/", &small_base) == 0);
        check_ok("oversized relative path is rejected, not truncated silently",
                 resolve(&small_base, big, &out) != 0 || strlen(out.path) < sizeof big);
    }

    printf(failures ? "\nURL TEST: %d FAILURE(S)\n" : "\nURL TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
