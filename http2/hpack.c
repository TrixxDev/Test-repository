/* HPACK header compression, encode side — see hpack.h. */
#include "hpack.h"

int hpack_put_int(uint8_t *out, size_t cap, size_t *pos,
                  int prefix_bits, uint8_t flag_bits, uint32_t value)
{
    if (*pos >= cap) return -1;
    uint32_t max_prefix = (1u << prefix_bits) - 1u;

    if (value < max_prefix) {
        out[*pos] = (uint8_t)(flag_bits | (uint8_t)value);
        (*pos)++;
        return 0;
    }

    out[*pos] = (uint8_t)(flag_bits | (uint8_t)max_prefix);
    (*pos)++;
    value -= max_prefix;
    while (value >= 128) {
        if (*pos >= cap) return -1;
        out[*pos] = (uint8_t)((value % 128u) | 0x80u);
        (*pos)++;
        value /= 128u;
    }
    if (*pos >= cap) return -1;
    out[*pos] = (uint8_t)value;
    (*pos)++;
    return 0;
}

int hpack_put_string(uint8_t *out, size_t cap, size_t *pos, const char *s, size_t len)
{
    /* Huffman bit (the string length's own 7-bit prefix, flag_bits=0) is
     * always clear -- see the header comment on why this client never
     * Huffman-encodes what it sends. */
    if (hpack_put_int(out, cap, pos, 7, 0x00, (uint32_t)len) != 0) return -1;
    if (*pos + len > cap) return -1;
    for (size_t i = 0; i < len; i++) out[(*pos)++] = (uint8_t)s[i];
    return 0;
}

int hpack_put_indexed(uint8_t *out, size_t cap, size_t *pos, unsigned index)
{
    /* RFC 7541 §6.1: "1" + a 7-bit-prefixed integer for the index. */
    return hpack_put_int(out, cap, pos, 7, 0x80, index);
}

int hpack_put_literal_indexed_name(uint8_t *out, size_t cap, size_t *pos,
                                   unsigned name_index, const char *value, size_t value_len)
{
    /* RFC 7541 §6.2.2: "0000" + a 4-bit-prefixed integer for the indexed
     * name, then the literal value string. */
    if (hpack_put_int(out, cap, pos, 4, 0x00, name_index) != 0) return -1;
    return hpack_put_string(out, cap, pos, value, value_len);
}
