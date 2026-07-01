/* CRC-32 (ISO 3309 / ITU-T V.42), the polynomial gzip uses for its trailer
 * (RFC 1952 §8). Portable, freestanding: only <stdint.h>/<stddef.h>, no
 * allocation, no OS calls -- same discipline as crypto/.
 *
 * Streaming API (init/update/final) so a caller can feed a gzip member's
 * decompressed bytes as they're produced, not after buffering the whole
 * body -- the same reason compress/inflate.c is itself incremental. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t crc;   /* running CRC, already inverted (~crc) at rest between calls is NOT
                      * how this is stored -- see crc32.c: the raw (uninverted) register
                      * is kept internally and only inverted in crc32_final(). */
} crc32_ctx;

void crc32_init(crc32_ctx *c);
void crc32_update(crc32_ctx *c, const void *data, size_t len);
uint32_t crc32_final(const crc32_ctx *c);

/* One-shot convenience. */
uint32_t crc32(const void *data, size_t len);
