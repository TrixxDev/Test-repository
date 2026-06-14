#include "string.h"
#include <stdint.h>

void *memset(void *dest, int value, size_t count)
{
    uint8_t *d = dest;
    while (count--)
        *d++ = (uint8_t)value;
    return dest;
}

void *memcpy(void *dest, const void *src, size_t count)
{
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (count--)
        *d++ = *s++;
    return dest;
}

void *memmove(void *dest, const void *src, size_t count)
{
    uint8_t *d = dest;
    const uint8_t *s = src;
    if (d < s) {
        while (count--)
            *d++ = *s++;
    } else {
        d += count;
        s += count;
        while (count--)
            *--d = *--s;
    }
    return dest;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int memcmp(const void *a, const void *b, size_t count)
{
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < count; i++) {
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i];
    }
    return 0;
}
