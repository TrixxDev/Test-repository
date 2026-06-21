#include "libc.h"
#include <stdint.h>

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++)) ;
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    /* Word-copy when both ends are 4-byte aligned — the common case for pixel
     * buffers (the compositor copies whole ~3 MB frames). ~4x fewer iterations
     * than the byte loop; falls back to bytes for the tail / unaligned inputs. */
    if ((((uintptr_t)d | (uintptr_t)s) & 3u) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;
        size_t w = n >> 2;
        while (w--) *dw++ = *sw++;
        d = (unsigned char *)dw;
        s = (const unsigned char *)sw;
        n &= 3u;
    }
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;
    /* Word-fill the aligned middle (clears/fills of pixel buffers are common). */
    if (((uintptr_t)d & 3u) == 0 && n >= 4) {
        uint32_t v = (uint32_t)(unsigned char)c;
        v |= v << 8; v |= v << 16;
        uint32_t *dw = (uint32_t *)d;
        size_t w = n >> 2;
        while (w--) *dw++ = v;
        d = (unsigned char *)dw;
        n &= 3u;
    }
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) { while (n--) *d++ = *s++; }
    else { d += n; s += n; while (n--) *--d = *--s; }
    return dst;
}
