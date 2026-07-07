/* RFC 4648 base64 encoding -- see base64.h. */
#include "base64.h"

static const char ALPHABET[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encoded_len(int inlen)
{
    return ((inlen + 2) / 3) * 4;
}

int base64_encode(const uint8_t *in, int inlen, char *out, int outcap)
{
    int need = base64_encoded_len(inlen);
    if (need > outcap) return -1;

    int i = 0, o = 0;
    while (i + 3 <= inlen) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[o++] = ALPHABET[(v >> 18) & 0x3f];
        out[o++] = ALPHABET[(v >> 12) & 0x3f];
        out[o++] = ALPHABET[(v >> 6) & 0x3f];
        out[o++] = ALPHABET[v & 0x3f];
        i += 3;
    }
    int rem = inlen - i;
    if (rem == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = ALPHABET[(v >> 18) & 0x3f];
        out[o++] = ALPHABET[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
        out[o++] = ALPHABET[(v >> 18) & 0x3f];
        out[o++] = ALPHABET[(v >> 12) & 0x3f];
        out[o++] = ALPHABET[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    return o;
}
