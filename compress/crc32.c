/* CRC-32 (ISO 3309), reflected form, polynomial 0xEDB88320 -- see crc32.h. */
#include "crc32.h"

/* The 256-entry lookup table is generated once, on first use, rather than
 * hand-written as a literal: 256 precomputed constants would be pure noise
 * to read and easy to transcribe wrong, whereas the generating loop is the
 * textbook definition of the reflected CRC-32 table and self-evidently
 * correct. No OS calls, no allocation -- safe for freestanding init. */
static uint32_t g_table[256];
static int      g_table_ready;

static void build_table(void)
{
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_table[n] = c;
    }
    g_table_ready = 1;
}

void crc32_init(crc32_ctx *c)
{
    if (!g_table_ready) build_table();
    c->crc = 0xFFFFFFFFu;   /* initial register, inverted at the end (final()) */
}

void crc32_update(crc32_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = c->crc;
    for (size_t i = 0; i < len; i++)
        crc = g_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    c->crc = crc;
}

uint32_t crc32_final(const crc32_ctx *c)
{
    return c->crc ^ 0xFFFFFFFFu;
}

uint32_t crc32(const void *data, size_t len)
{
    crc32_ctx c;
    crc32_init(&c);
    crc32_update(&c, data, len);
    return crc32_final(&c);
}
