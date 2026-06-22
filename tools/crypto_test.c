/* Host-side crypto test: verifies the portable crypto/ primitives against known
 * answer vectors (NIST FIPS 180-4 for SHA-256, RFC 4231 for HMAC-SHA256). Runs
 * natively on the build host -- no QEMU, no OS -- so each primitive is checked in
 * isolation. Build/run: `make crypto-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"
#include "hmac_sha256.h"

static int failures;

static void tohex(const uint8_t *b, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}

static void check(const char *name, const uint8_t *got, int n, const char *want)
{
    char hex[129];
    tohex(got, n, hex);
    if (strcmp(hex, want) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want);
        failures++;
    }
}

/* Parse a hex string into bytes; returns the byte count. */
static int unhex(const char *s, uint8_t *out)
{
    int n = 0;
    for (; s[0] && s[1]; s += 2) {
        int hi = s[0] <= '9' ? s[0]-'0' : (s[0]|32)-'a'+10;
        int lo = s[1] <= '9' ? s[1]-'0' : (s[1]|32)-'a'+10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

int main(void)
{
    uint8_t d[32];

    printf("SHA-256 (NIST FIPS 180-4):\n");
    sha256("", 0, d);
    check("\"\"", d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256("abc", 3, d);
    check("\"abc\"", d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *s2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(s2, strlen(s2), d);
    check("56-byte string", d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    {   /* one million 'a' */
        sha256_ctx c; sha256_init(&c);
        char buf[1000]; memset(buf, 'a', sizeof(buf));
        for (int i = 0; i < 1000; i++) sha256_update(&c, buf, sizeof(buf));
        sha256_final(&c, d);
        check("1,000,000 x 'a'", d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    printf("HMAC-SHA256 (RFC 4231):\n");
    {   /* Test Case 1 */
        uint8_t key[20]; memset(key, 0x0b, sizeof(key));
        hmac_sha256(key, 20, "Hi There", 8, d);
        check("case 1", d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    {   /* Test Case 2 */
        hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
        check("case 2", d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
    {   /* Test Case 3: 20x 0xaa key, 50x 0xdd data */
        uint8_t key[20], data[50]; memset(key, 0xaa, 20); memset(data, 0xdd, 50);
        hmac_sha256(key, 20, data, 50, d);
        check("case 3", d, 32, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }
    {   /* Test Case 4: key 0x01..0x19 (25 bytes), 50x 0xcd data */
        uint8_t key[25], data[50];
        for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
        memset(data, 0xcd, 50);
        hmac_sha256(key, 25, data, 50, d);
        check("case 4", d, 32, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    }
    {   /* Test Case 6: 131-byte key (>block), "Test Using Larger Than Block-Size Key - Hash Key First" */
        uint8_t key[131]; memset(key, 0xaa, sizeof(key));
        const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
        hmac_sha256(key, 131, m, strlen(m), d);
        check("case 6 (long key)", d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    (void)unhex;
    printf(failures ? "\nCRYPTO TEST: %d FAILURE(S)\n" : "\nCRYPTO TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
