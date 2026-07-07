/* gzip container (RFC 1952) around a raw DEFLATE stream (compress/inflate.c).
 * Incremental like inflate.c itself: the 10-byte fixed header, the optional
 * FEXTRA/FNAME/FCOMMENT/FHCRC fields, the compressed body, and the 8-byte
 * CRC32+ISIZE trailer can each arrive split across arbitrarily many feed()
 * calls. Portable, freestanding: only <stdint.h>/<stddef.h>, no allocation.
 *
 * Only ever verifies against the FIRST member (RFC 1952 §2.2 allows a file
 * to concatenate several); that matches every real HTTP server's
 * Content-Encoding: gzip body, which is always exactly one member. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "inflate.h"
#include "crc32.h"

typedef enum {
    GZ_HDR_FIXED = 0,     /* ID1 ID2 CM FLG MTIME(4) XFL OS -- 10 bytes */
    GZ_HDR_FEXTRA_LEN,    /* XLEN, little-endian uint16 (if FLG.FEXTRA)  */
    GZ_HDR_FEXTRA_SKIP,
    GZ_HDR_FNAME,         /* zero-terminated (if FLG.FNAME)              */
    GZ_HDR_FCOMMENT,      /* zero-terminated (if FLG.FCOMMENT)           */
    GZ_HDR_FHCRC,         /* 2 bytes (if FLG.FHCRC); not verified        */
    GZ_BODY,
    GZ_TRAILER,           /* CRC32(4) + ISIZE(4), both little-endian     */
    GZ_DONE,
    GZ_ERROR
} gzip_mode;

typedef struct {
    gzip_mode mode;
    uint8_t   hdrbuf[10];
    int       hdrpos;
    uint8_t   flg;
    unsigned  xlen, xlen_left;
    int       xlen_read;
    int       fhcrc_left;
    uint8_t   trailer[8];
    int       trailer_pos;

    inflate_ctx inf;
    crc32_ctx   crc;
    uint32_t    total_out;   /* decompressed bytes so far, mod 2^32 (RFC 1952 ISIZE) */
} gzip_ctx;

void gzip_init(gzip_ctx *g);

/* Same contract as inflate_feed() (compress/inflate.h): feeds `in_len` new
 * gzip-member bytes, decompresses into `out` (capacity `out_cap`).
 *   *in_used -- bytes of `in` consumed this call
 *   *out_len -- decompressed bytes written to `out`
 *   *done    -- 1 once the trailer has been read AND verified
 * Returns 0, or -1 on a malformed member, a bad magic/CM, or a CRC32/ISIZE
 * mismatch against the trailer -- any of which stick `g` in an error state. */
int gzip_feed(gzip_ctx *g, const uint8_t *in, size_t in_len,
             uint8_t *out, size_t out_cap,
             size_t *in_used, size_t *out_len, int *done);
