/* HPACK Huffman decoding — see huffman.h.
 *
 * The table just below is RFC 7541 Appendix B verbatim (mechanically
 * extracted from the RFC's own text, not hand-transcribed -- see
 * huffman.h). Each entry is that symbol's canonical Huffman code, given as
 * an integer with the code's own bits packed into its low `len` bits (the
 * same convention the RFC's own table uses), plus that code's bit length.
 * Entry 256 is EOS -- never a decode target on its own (see below), listed
 * only so the table stays a complete, directly-indexed copy of Appendix B. */
#include "huffman.h"

/* Generated directly from RFC 7541 Appendix B -- do not hand-edit. */
static const struct { uint32_t code; uint8_t len; } hpack_huffman_table[257] = {
    { 0x00001ff8u, 13 },  /* 0 */
    { 0x007fffd8u, 23 },  /* 1 */
    { 0x0fffffe2u, 28 },  /* 2 */
    { 0x0fffffe3u, 28 },  /* 3 */
    { 0x0fffffe4u, 28 },  /* 4 */
    { 0x0fffffe5u, 28 },  /* 5 */
    { 0x0fffffe6u, 28 },  /* 6 */
    { 0x0fffffe7u, 28 },  /* 7 */
    { 0x0fffffe8u, 28 },  /* 8 */
    { 0x00ffffeau, 24 },  /* 9 */
    { 0x3ffffffcu, 30 },  /* 10 */
    { 0x0fffffe9u, 28 },  /* 11 */
    { 0x0fffffeau, 28 },  /* 12 */
    { 0x3ffffffdu, 30 },  /* 13 */
    { 0x0fffffebu, 28 },  /* 14 */
    { 0x0fffffecu, 28 },  /* 15 */
    { 0x0fffffedu, 28 },  /* 16 */
    { 0x0fffffeeu, 28 },  /* 17 */
    { 0x0fffffefu, 28 },  /* 18 */
    { 0x0ffffff0u, 28 },  /* 19 */
    { 0x0ffffff1u, 28 },  /* 20 */
    { 0x0ffffff2u, 28 },  /* 21 */
    { 0x3ffffffeu, 30 },  /* 22 */
    { 0x0ffffff3u, 28 },  /* 23 */
    { 0x0ffffff4u, 28 },  /* 24 */
    { 0x0ffffff5u, 28 },  /* 25 */
    { 0x0ffffff6u, 28 },  /* 26 */
    { 0x0ffffff7u, 28 },  /* 27 */
    { 0x0ffffff8u, 28 },  /* 28 */
    { 0x0ffffff9u, 28 },  /* 29 */
    { 0x0ffffffau, 28 },  /* 30 */
    { 0x0ffffffbu, 28 },  /* 31 */
    { 0x00000014u,  6 },  /* 32 */
    { 0x000003f8u, 10 },  /* 33 */
    { 0x000003f9u, 10 },  /* 34 */
    { 0x00000ffau, 12 },  /* 35 */
    { 0x00001ff9u, 13 },  /* 36 */
    { 0x00000015u,  6 },  /* 37 */
    { 0x000000f8u,  8 },  /* 38 */
    { 0x000007fau, 11 },  /* 39 */
    { 0x000003fau, 10 },  /* 40 */
    { 0x000003fbu, 10 },  /* 41 */
    { 0x000000f9u,  8 },  /* 42 */
    { 0x000007fbu, 11 },  /* 43 */
    { 0x000000fau,  8 },  /* 44 */
    { 0x00000016u,  6 },  /* 45 */
    { 0x00000017u,  6 },  /* 46 */
    { 0x00000018u,  6 },  /* 47 */
    { 0x00000000u,  5 },  /* 48 */
    { 0x00000001u,  5 },  /* 49 */
    { 0x00000002u,  5 },  /* 50 */
    { 0x00000019u,  6 },  /* 51 */
    { 0x0000001au,  6 },  /* 52 */
    { 0x0000001bu,  6 },  /* 53 */
    { 0x0000001cu,  6 },  /* 54 */
    { 0x0000001du,  6 },  /* 55 */
    { 0x0000001eu,  6 },  /* 56 */
    { 0x0000001fu,  6 },  /* 57 */
    { 0x0000005cu,  7 },  /* 58 */
    { 0x000000fbu,  8 },  /* 59 */
    { 0x00007ffcu, 15 },  /* 60 */
    { 0x00000020u,  6 },  /* 61 */
    { 0x00000ffbu, 12 },  /* 62 */
    { 0x000003fcu, 10 },  /* 63 */
    { 0x00001ffau, 13 },  /* 64 */
    { 0x00000021u,  6 },  /* 65 */
    { 0x0000005du,  7 },  /* 66 */
    { 0x0000005eu,  7 },  /* 67 */
    { 0x0000005fu,  7 },  /* 68 */
    { 0x00000060u,  7 },  /* 69 */
    { 0x00000061u,  7 },  /* 70 */
    { 0x00000062u,  7 },  /* 71 */
    { 0x00000063u,  7 },  /* 72 */
    { 0x00000064u,  7 },  /* 73 */
    { 0x00000065u,  7 },  /* 74 */
    { 0x00000066u,  7 },  /* 75 */
    { 0x00000067u,  7 },  /* 76 */
    { 0x00000068u,  7 },  /* 77 */
    { 0x00000069u,  7 },  /* 78 */
    { 0x0000006au,  7 },  /* 79 */
    { 0x0000006bu,  7 },  /* 80 */
    { 0x0000006cu,  7 },  /* 81 */
    { 0x0000006du,  7 },  /* 82 */
    { 0x0000006eu,  7 },  /* 83 */
    { 0x0000006fu,  7 },  /* 84 */
    { 0x00000070u,  7 },  /* 85 */
    { 0x00000071u,  7 },  /* 86 */
    { 0x00000072u,  7 },  /* 87 */
    { 0x000000fcu,  8 },  /* 88 */
    { 0x00000073u,  7 },  /* 89 */
    { 0x000000fdu,  8 },  /* 90 */
    { 0x00001ffbu, 13 },  /* 91 */
    { 0x0007fff0u, 19 },  /* 92 */
    { 0x00001ffcu, 13 },  /* 93 */
    { 0x00003ffcu, 14 },  /* 94 */
    { 0x00000022u,  6 },  /* 95 */
    { 0x00007ffdu, 15 },  /* 96 */
    { 0x00000003u,  5 },  /* 97 */
    { 0x00000023u,  6 },  /* 98 */
    { 0x00000004u,  5 },  /* 99 */
    { 0x00000024u,  6 },  /* 100 */
    { 0x00000005u,  5 },  /* 101 */
    { 0x00000025u,  6 },  /* 102 */
    { 0x00000026u,  6 },  /* 103 */
    { 0x00000027u,  6 },  /* 104 */
    { 0x00000006u,  5 },  /* 105 */
    { 0x00000074u,  7 },  /* 106 */
    { 0x00000075u,  7 },  /* 107 */
    { 0x00000028u,  6 },  /* 108 */
    { 0x00000029u,  6 },  /* 109 */
    { 0x0000002au,  6 },  /* 110 */
    { 0x00000007u,  5 },  /* 111 */
    { 0x0000002bu,  6 },  /* 112 */
    { 0x00000076u,  7 },  /* 113 */
    { 0x0000002cu,  6 },  /* 114 */
    { 0x00000008u,  5 },  /* 115 */
    { 0x00000009u,  5 },  /* 116 */
    { 0x0000002du,  6 },  /* 117 */
    { 0x00000077u,  7 },  /* 118 */
    { 0x00000078u,  7 },  /* 119 */
    { 0x00000079u,  7 },  /* 120 */
    { 0x0000007au,  7 },  /* 121 */
    { 0x0000007bu,  7 },  /* 122 */
    { 0x00007ffeu, 15 },  /* 123 */
    { 0x000007fcu, 11 },  /* 124 */
    { 0x00003ffdu, 14 },  /* 125 */
    { 0x00001ffdu, 13 },  /* 126 */
    { 0x0ffffffcu, 28 },  /* 127 */
    { 0x000fffe6u, 20 },  /* 128 */
    { 0x003fffd2u, 22 },  /* 129 */
    { 0x000fffe7u, 20 },  /* 130 */
    { 0x000fffe8u, 20 },  /* 131 */
    { 0x003fffd3u, 22 },  /* 132 */
    { 0x003fffd4u, 22 },  /* 133 */
    { 0x003fffd5u, 22 },  /* 134 */
    { 0x007fffd9u, 23 },  /* 135 */
    { 0x003fffd6u, 22 },  /* 136 */
    { 0x007fffdau, 23 },  /* 137 */
    { 0x007fffdbu, 23 },  /* 138 */
    { 0x007fffdcu, 23 },  /* 139 */
    { 0x007fffddu, 23 },  /* 140 */
    { 0x007fffdeu, 23 },  /* 141 */
    { 0x00ffffebu, 24 },  /* 142 */
    { 0x007fffdfu, 23 },  /* 143 */
    { 0x00ffffecu, 24 },  /* 144 */
    { 0x00ffffedu, 24 },  /* 145 */
    { 0x003fffd7u, 22 },  /* 146 */
    { 0x007fffe0u, 23 },  /* 147 */
    { 0x00ffffeeu, 24 },  /* 148 */
    { 0x007fffe1u, 23 },  /* 149 */
    { 0x007fffe2u, 23 },  /* 150 */
    { 0x007fffe3u, 23 },  /* 151 */
    { 0x007fffe4u, 23 },  /* 152 */
    { 0x001fffdcu, 21 },  /* 153 */
    { 0x003fffd8u, 22 },  /* 154 */
    { 0x007fffe5u, 23 },  /* 155 */
    { 0x003fffd9u, 22 },  /* 156 */
    { 0x007fffe6u, 23 },  /* 157 */
    { 0x007fffe7u, 23 },  /* 158 */
    { 0x00ffffefu, 24 },  /* 159 */
    { 0x003fffdau, 22 },  /* 160 */
    { 0x001fffddu, 21 },  /* 161 */
    { 0x000fffe9u, 20 },  /* 162 */
    { 0x003fffdbu, 22 },  /* 163 */
    { 0x003fffdcu, 22 },  /* 164 */
    { 0x007fffe8u, 23 },  /* 165 */
    { 0x007fffe9u, 23 },  /* 166 */
    { 0x001fffdeu, 21 },  /* 167 */
    { 0x007fffeau, 23 },  /* 168 */
    { 0x003fffddu, 22 },  /* 169 */
    { 0x003fffdeu, 22 },  /* 170 */
    { 0x00fffff0u, 24 },  /* 171 */
    { 0x001fffdfu, 21 },  /* 172 */
    { 0x003fffdfu, 22 },  /* 173 */
    { 0x007fffebu, 23 },  /* 174 */
    { 0x007fffecu, 23 },  /* 175 */
    { 0x001fffe0u, 21 },  /* 176 */
    { 0x001fffe1u, 21 },  /* 177 */
    { 0x003fffe0u, 22 },  /* 178 */
    { 0x001fffe2u, 21 },  /* 179 */
    { 0x007fffedu, 23 },  /* 180 */
    { 0x003fffe1u, 22 },  /* 181 */
    { 0x007fffeeu, 23 },  /* 182 */
    { 0x007fffefu, 23 },  /* 183 */
    { 0x000fffeau, 20 },  /* 184 */
    { 0x003fffe2u, 22 },  /* 185 */
    { 0x003fffe3u, 22 },  /* 186 */
    { 0x003fffe4u, 22 },  /* 187 */
    { 0x007ffff0u, 23 },  /* 188 */
    { 0x003fffe5u, 22 },  /* 189 */
    { 0x003fffe6u, 22 },  /* 190 */
    { 0x007ffff1u, 23 },  /* 191 */
    { 0x03ffffe0u, 26 },  /* 192 */
    { 0x03ffffe1u, 26 },  /* 193 */
    { 0x000fffebu, 20 },  /* 194 */
    { 0x0007fff1u, 19 },  /* 195 */
    { 0x003fffe7u, 22 },  /* 196 */
    { 0x007ffff2u, 23 },  /* 197 */
    { 0x003fffe8u, 22 },  /* 198 */
    { 0x01ffffecu, 25 },  /* 199 */
    { 0x03ffffe2u, 26 },  /* 200 */
    { 0x03ffffe3u, 26 },  /* 201 */
    { 0x03ffffe4u, 26 },  /* 202 */
    { 0x07ffffdeu, 27 },  /* 203 */
    { 0x07ffffdfu, 27 },  /* 204 */
    { 0x03ffffe5u, 26 },  /* 205 */
    { 0x00fffff1u, 24 },  /* 206 */
    { 0x01ffffedu, 25 },  /* 207 */
    { 0x0007fff2u, 19 },  /* 208 */
    { 0x001fffe3u, 21 },  /* 209 */
    { 0x03ffffe6u, 26 },  /* 210 */
    { 0x07ffffe0u, 27 },  /* 211 */
    { 0x07ffffe1u, 27 },  /* 212 */
    { 0x03ffffe7u, 26 },  /* 213 */
    { 0x07ffffe2u, 27 },  /* 214 */
    { 0x00fffff2u, 24 },  /* 215 */
    { 0x001fffe4u, 21 },  /* 216 */
    { 0x001fffe5u, 21 },  /* 217 */
    { 0x03ffffe8u, 26 },  /* 218 */
    { 0x03ffffe9u, 26 },  /* 219 */
    { 0x0ffffffdu, 28 },  /* 220 */
    { 0x07ffffe3u, 27 },  /* 221 */
    { 0x07ffffe4u, 27 },  /* 222 */
    { 0x07ffffe5u, 27 },  /* 223 */
    { 0x000fffecu, 20 },  /* 224 */
    { 0x00fffff3u, 24 },  /* 225 */
    { 0x000fffedu, 20 },  /* 226 */
    { 0x001fffe6u, 21 },  /* 227 */
    { 0x003fffe9u, 22 },  /* 228 */
    { 0x001fffe7u, 21 },  /* 229 */
    { 0x001fffe8u, 21 },  /* 230 */
    { 0x007ffff3u, 23 },  /* 231 */
    { 0x003fffeau, 22 },  /* 232 */
    { 0x003fffebu, 22 },  /* 233 */
    { 0x01ffffeeu, 25 },  /* 234 */
    { 0x01ffffefu, 25 },  /* 235 */
    { 0x00fffff4u, 24 },  /* 236 */
    { 0x00fffff5u, 24 },  /* 237 */
    { 0x03ffffeau, 26 },  /* 238 */
    { 0x007ffff4u, 23 },  /* 239 */
    { 0x03ffffebu, 26 },  /* 240 */
    { 0x07ffffe6u, 27 },  /* 241 */
    { 0x03ffffecu, 26 },  /* 242 */
    { 0x03ffffedu, 26 },  /* 243 */
    { 0x07ffffe7u, 27 },  /* 244 */
    { 0x07ffffe8u, 27 },  /* 245 */
    { 0x07ffffe9u, 27 },  /* 246 */
    { 0x07ffffeau, 27 },  /* 247 */
    { 0x07ffffebu, 27 },  /* 248 */
    { 0x0ffffffeu, 28 },  /* 249 */
    { 0x07ffffecu, 27 },  /* 250 */
    { 0x07ffffedu, 27 },  /* 251 */
    { 0x07ffffeeu, 27 },  /* 252 */
    { 0x07ffffefu, 27 },  /* 253 */
    { 0x07fffff0u, 27 },  /* 254 */
    { 0x03ffffeeu, 26 },  /* 255 */
    { 0x3fffffffu, 30 },  /* 256 */
};

/* Bit-by-bit trie walk: accumulate one bit at a time into a candidate
 * (code, len), and after each bit, scan the 256 real symbols (never 256/EOS
 * itself -- RFC 7541 §5.2 forbids a sender from ever encoding it) for an
 * exact (code, len) match. Huffman codes are prefix-free, so at most one
 * symbol can ever match a given (code, len) pair; a linear scan is
 * correctness-first and cheap enough for the short header strings this
 * client handles (worst case a few thousand comparisons per symbol, not a
 * hot path). */
int hpack_huffman_decode(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t outcap, size_t *outlen)
{
    size_t total_bits = inlen * 8;
    size_t bitpos = 0;
    size_t n = 0;
    uint32_t code = 0;
    int len = 0;

    while (bitpos < total_bits) {
        int bit = (in[bitpos / 8] >> (7 - (bitpos % 8))) & 1;
        code = (code << 1) | (uint32_t)bit;
        len++;
        bitpos++;

        int matched = -1;
        for (int sym = 0; sym < 256; sym++) {
            if (hpack_huffman_table[sym].len == len && hpack_huffman_table[sym].code == code) {
                matched = sym;
                break;
            }
        }
        if (matched >= 0) {
            if (n >= outcap) return -1;
            out[n++] = (uint8_t)matched;
            code = 0;
            len = 0;
            continue;
        }
        if (len > 30) return -1;
    }

    /* Whatever's left (0-7 bits) must be all 1s -- a prefix of the EOS
     * code, which is itself 30 consecutive 1-bits (RFC 7541 §5.2). */
    if (len > 7) return -1;
    if (len > 0) {
        uint32_t mask = (1u << len) - 1u;
        if ((code & mask) != mask) return -1;
    }

    *outlen = n;
    return 0;
}
