/* Host-side cookie jar test (RFC 6265): domain/path matching, Max-Age vs
 * Expires precedence, deletion, overwrite, LRU eviction, Secure/host-only
 * enforcement, and rejecting a Domain attribute for an unrelated host.
 * Build/run: `make cookiejar-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cookiejar.h"

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

static void check_str(const char *name, const char *got, int gotlen, const char *want)
{
    int wl = (int)strlen(want);
    int ok = gotlen == wl && memcmp(got, want, (size_t)wl) == 0;
    if (ok) printf("  PASS  %s\n", name);
    else {
        char g[256]; int n = gotlen < (int)sizeof g - 1 ? gotlen : (int)sizeof g - 1;
        memcpy(g, got, (size_t)n); g[n] = 0;
        printf("  FAIL  %s\n        got  \"%s\"\n        want \"%s\"\n", name, g, want);
        failures++;
    }
}

int main(void)
{
    printf("Cookie jar (RFC 6265):\n");

    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "sid=abc123", 10, "example.com", "/", 0, 1000);
        char out[256];
        int n = cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out);
        check_str("basic name=value, host-only, default path", out, n, "sid=abc123");

        int n2 = cookie_jar_build_header(&jar, "sub.example.com", "/", 0, 1000, out, sizeof out);
        check_ok("host-only cookie NOT sent to a subdomain", n2 == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Domain=example.com", 23, "www.example.com", "/", 0, 1000);
        char out[256];
        int n = cookie_jar_build_header(&jar, "www.example.com", "/", 0, 1000, out, sizeof out);
        check_str("explicit Domain matches the setting host itself", out, n, "a=1");
        int n2 = cookie_jar_build_header(&jar, "other.example.com", "/", 0, 1000, out, sizeof out);
        check_str("explicit Domain matches a sibling subdomain too", out, n2, "a=1");
        int n3 = cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out);
        check_str("explicit Domain matches the bare parent domain", out, n3, "a=1");
        int n4 = cookie_jar_build_header(&jar, "notexample.com", "/", 0, 1000, out, sizeof out);
        check_ok("explicit Domain does NOT match an unrelated host with the same suffix chars", n4 == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Domain=.example.com", 24, "www.example.com", "/", 0, 1000);
        char out[256];
        int n = cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out);
        check_str("leading dot on Domain is ignored (RFC 6265 SS5.2.3)", out, n, "a=1");
    }
    {
        /* a server may not set a cookie for a domain it doesn't control */
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Domain=evil.com", 20, "example.com", "/", 0, 1000);
        char out[256];
        int n = cookie_jar_build_header(&jar, "evil.com", "/", 0, 1000, out, sizeof out);
        check_ok("Domain attribute for an unrelated host is rejected entirely", n == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Path=/app", 14, "example.com", "/app/login", 0, 1000);
        char out[256];
        check_str("explicit Path: request under it matches",
                  out, cookie_jar_build_header(&jar, "example.com", "/app/settings", 0, 1000, out, sizeof out), "a=1");
        check_str("explicit Path: exact match",
                  out, cookie_jar_build_header(&jar, "example.com", "/app", 0, 1000, out, sizeof out), "a=1");
        check_ok("explicit Path: sibling path with shared prefix does NOT match (no slash boundary)",
                 cookie_jar_build_header(&jar, "example.com", "/application", 0, 1000, out, sizeof out) == 0);
        check_ok("explicit Path: unrelated path does not match",
                 cookie_jar_build_header(&jar, "example.com", "/other", 0, 1000, out, sizeof out) == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1", 3, "example.com", "/a/b/c", 0, 1000);
        char out[256];
        check_str("default-path: '/a/b/c' -> '/a/b'",
                  out, cookie_jar_build_header(&jar, "example.com", "/a/b", 0, 1000, out, sizeof out), "a=1");
        check_ok("default-path from '/a/b/c' does not reach '/a' alone",
                 cookie_jar_build_header(&jar, "example.com", "/a", 0, 1000, out, sizeof out) == 0);

        cookie_jar jar2; cookie_jar_init(&jar2);
        cookie_jar_set(&jar2, "b=2", 3, "example.com", "/onlyone", 0, 1000);
        check_str("default-path: a single-segment path -> '/'",
                  out, cookie_jar_build_header(&jar2, "example.com", "/elsewhere", 0, 1000, out, sizeof out), "b=2");
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Max-Age=100", 16, "example.com", "/", 0, 1000);
        char out[256];
        check_str("Max-Age: still valid just before expiry",
                  out, cookie_jar_build_header(&jar, "example.com", "/", 0, 1099, out, sizeof out), "a=1");
        check_ok("Max-Age: expired exactly at expiry",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 1100, out, sizeof out) == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1", 3, "example.com", "/", 0, 1000);
        cookie_jar_set(&jar, "a=2; Max-Age=0", 14, "example.com", "/", 0, 1000);
        char out[256];
        check_ok("Max-Age=0 deletes an existing cookie of the same identity",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out) == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Expires=Thu, 01 Jan 1970 00:00:10 GMT", 43, "example.com", "/", 0, 5);
        char out[256];
        check_str("Expires: parsed HTTP-date, still valid before it",
                  out, cookie_jar_build_header(&jar, "example.com", "/", 0, 9, out, sizeof out), "a=1");
        check_ok("Expires: expired at/after the parsed instant",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 10, out, sizeof out) == 0);
    }
    {
        /* RFC 6265 SS5.3: Max-Age takes priority over Expires when both present */
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Max-Age=5; Expires=Wed, 21 Oct 2026 07:28:00 GMT", 54,
                       "example.com", "/", 0, 1000);
        char out[256];
        check_str("Max-Age wins over Expires: still valid just before Max-Age's expiry",
                  out, cookie_jar_build_header(&jar, "example.com", "/", 0, 1004, out, sizeof out), "a=1");
        check_ok("Max-Age wins over Expires: expired per Max-Age despite Expires being far future",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 1005, out, sizeof out) == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1; Secure", 11, "example.com", "/", 1, 1000);
        char out[256];
        check_str("Secure cookie sent over https",
                  out, cookie_jar_build_header(&jar, "example.com", "/", 1, 1000, out, sizeof out), "a=1");
        check_ok("Secure cookie withheld over plain http",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out) == 0);
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1", 3, "example.com", "/", 0, 1000);
        cookie_jar_set(&jar, "a=2", 3, "example.com", "/", 0, 1001);   /* same identity: overwrite */
        char out[256];
        check_str("same (name,domain,path) overwrites the value, not appends",
                  out, cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out), "a=2");
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "a=1", 3, "x.com", "/", 0, 1000);
        cookie_jar_set(&jar, "b=2", 3, "x.com", "/", 0, 1000);
        char out[256];
        int n = cookie_jar_build_header(&jar, "x.com", "/", 0, 1000, out, sizeof out);
        int ok = (n == 8 && memcmp(out, "a=1; b=2", 8) == 0) || (n == 8 && memcmp(out, "b=2; a=1", 8) == 0);
        check_ok("two cookies joined with '; '", ok);
    }
    {
        /* Each cookie gets its own Path so a request can touch (or check)
         * exactly one entry at a time -- otherwise a single header build
         * would LRU-refresh every matching cookie together and the "which
         * one is truly least-recently-used" signal would be lost. */
        cookie_jar jar; cookie_jar_init(&jar);
        char setv[24], path[16], out[64];
        for (int i = 0; i < COOKIE_JAR_N; i++) {
            int slen = 0;
            setv[slen++] = 'k'; setv[slen++] = (char)('0' + (i / 10)); setv[slen++] = (char)('0' + (i % 10));
            setv[slen++] = '='; setv[slen++] = 'v'; setv[slen++] = ';'; setv[slen++] = ' ';
            const char *p = "Path=/p"; for (int k = 0; p[k]; k++) setv[slen++] = p[k];
            setv[slen++] = (char)('0' + (i / 10)); setv[slen++] = (char)('0' + (i % 10));
            path[0] = '/'; path[1] = 'p'; path[2] = (char)('0' + (i / 10)); path[3] = (char)('0' + (i % 10)); path[4] = 0;
            cookie_jar_set(&jar, setv, slen, "x.com", path, 0, 1000 + (uint64_t)i);
        }
        check_str("jar full: cookie #0 present via its own path (nothing evicted yet)",
                  out, cookie_jar_build_header(&jar, "x.com", "/p00", 0, 2000, out, sizeof out), "k00=v");
        /* that build just touched (LRU-refreshed) k00; the true least-
         * recently-used is now k01, never touched since it was set */
        char setv99[32]; int slen99 = 0;
        { const char *s = "k99=v; Path=/p99"; while (s[slen99]) { setv99[slen99] = s[slen99]; slen99++; } }
        cookie_jar_set(&jar, setv99, slen99, "x.com", "/p99", 0, 3000);
        check_str("LRU eviction: recently-touched cookie #0 survives",
                  out, cookie_jar_build_header(&jar, "x.com", "/p00", 0, 3000, out, sizeof out), "k00=v");
        check_ok("LRU eviction: untouched cookie #1 was evicted to make room",
                 cookie_jar_build_header(&jar, "x.com", "/p01", 0, 3000, out, sizeof out) == 0);
        check_str("LRU eviction: the newly-set cookie is present",
                  out, cookie_jar_build_header(&jar, "x.com", "/p99", 0, 3000, out, sizeof out), "k99=v");
    }
    {
        cookie_jar jar; cookie_jar_init(&jar);
        cookie_jar_set(&jar, "noequalsatall", 13, "example.com", "/", 0, 1000);   /* malformed: no '=' */
        char out[256];
        check_ok("malformed Set-Cookie (no '=') is ignored, not a crash",
                 cookie_jar_build_header(&jar, "example.com", "/", 0, 1000, out, sizeof out) == 0);
    }

    printf(failures ? "\nCOOKIE JAR TEST: %d FAILURE(S)\n" : "\nCOOKIE JAR TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
