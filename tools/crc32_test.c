/* Host-side CRC-32 test: the standard check value plus streaming/one-shot
 * equivalence. Build/run: `make crc32-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crc32.h"

static int failures;

static void check_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got == want) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  0x%08x\n        want 0x%08x\n", name, got, want);
        failures++;
    }
}

int main(void)
{
    printf("CRC-32 (ISO 3309):\n");

    /* the standard check value: CRC32("123456789") == 0xCBF43926 */
    check_u32("check value \"123456789\"", crc32("123456789", 9), 0xCBF43926u);

    check_u32("empty input", crc32("", 0), 0x00000000u);
    check_u32("single byte 'a'", crc32("a", 1), 0xE8B7BE43u);

    /* a well-known gzip-world value: CRC32("") over a zero-length payload is
     * what an empty gzip member's trailer carries -- already covered above,
     * but pin the exact ASCII bytes used by RFC 1952-flavoured tools too. */
    check_u32("\"The quick brown fox...\"",
              crc32("The quick brown fox jumps over the lazy dog", 43), 0x414FA339u);

    /* streaming update must match the one-shot result regardless of how the
     * input is chopped up -- this is the property gzip decoding depends on,
     * since the decompressed body arrives in arbitrary TCP-sized pieces. */
    {
        const char *msg = "The quick brown fox jumps over the lazy dog";
        int len = 43;
        uint32_t want = crc32(msg, (size_t)len);

        crc32_ctx c;
        crc32_init(&c);
        for (int i = 0; i < len; i++) crc32_update(&c, msg + i, 1);   /* byte-at-a-time */
        check_u32("streaming (1 byte at a time) == one-shot", crc32_final(&c), want);

        crc32_ctx c2;
        crc32_init(&c2);
        crc32_update(&c2, msg, 17);
        crc32_update(&c2, msg + 17, len - 17);
        check_u32("streaming (2 uneven chunks) == one-shot", crc32_final(&c2), want);
    }

    printf(failures ? "\nCRC32 TEST: %d FAILURE(S)\n" : "\nCRC32 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
