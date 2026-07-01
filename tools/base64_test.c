/* Host-side base64 test: RFC 4648 SS10's own published test vectors, plus a
 * couple of realistic "user:pass" Basic-auth strings. Build/run:
 * `make base64-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "base64.h"

static int failures;

static void check(const char *name, const char *in, const char *want)
{
    int inlen = (int)strlen(in);
    int need = base64_encoded_len(inlen);
    char out[64];
    int n = base64_encode((const uint8_t*)in, inlen, out, sizeof out);
    int wantlen = (int)strlen(want);
    int ok = n == wantlen && n == need && memcmp(out, want, (size_t)n) == 0;
    if (ok) {
        printf("  PASS  %s\n", name);
    } else {
        char g[64]; int gn = n > 0 ? n : 0; if (gn > 63) gn = 63;
        memcpy(g, out, (size_t)gn); g[gn] = 0;
        printf("  FAIL  %s\n        got  \"%s\" (n=%d)\n        want \"%s\"\n", name, g, n, want);
        failures++;
    }
}

int main(void)
{
    printf("base64 (RFC 4648):\n");

    /* RFC 4648 SS10's own test vectors */
    check("\"\" -> \"\"", "", "");
    check("\"f\" -> \"Zg==\"", "f", "Zg==");
    check("\"fo\" -> \"Zm8=\"", "fo", "Zm8=");
    check("\"foo\" -> \"Zm9v\"", "foo", "Zm9v");
    check("\"foob\" -> \"Zm9vYg==\"", "foob", "Zm9vYg==");
    check("\"fooba\" -> \"Zm9vYmE=\"", "fooba", "Zm9vYmE=");
    check("\"foobar\" -> \"Zm9vYmFy\"", "foobar", "Zm9vYmFy");

    /* realistic Basic-auth "user:pass" strings */
    check("\"user:pass\"", "user:pass", "dXNlcjpwYXNz");
    check("\"alice:s3cr3t\"", "alice:s3cr3t", "YWxpY2U6czNjcjN0");

    {
        /* an output buffer exactly one byte too small must be rejected, not
         * silently truncated */
        char out[3];
        int n = base64_encode((const uint8_t*)"foo", 3, out, sizeof out);
        printf("  %s  undersized output buffer -> -1 (not silent truncation)\n", n == -1 ? "PASS" : "FAIL");
        if (n != -1) failures++;
    }

    printf(failures ? "\nBASE64 TEST: %d FAILURE(S)\n" : "\nBASE64 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
