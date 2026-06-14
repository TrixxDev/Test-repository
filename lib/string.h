/* Minimal freestanding string/memory helpers. */
#pragma once
#include <stddef.h>

void  *memset(void *dest, int value, size_t count);
void  *memcpy(void *dest, const void *src, size_t count);
void  *memmove(void *dest, const void *src, size_t count);
size_t strlen(const char *s);
int    strcmp(const char *a, const char *b);
