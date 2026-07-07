/* HPACK Huffman coding (RFC 7541 §5.2, Appendix B) — decode side only —
 * Phase 17.2.1.
 *
 * Aurora's own HPACK encoder (hpack.c) never sets the Huffman bit on a
 * string it sends (see hpack.h's header comment) -- Huffman coding is
 * optional for a sender, RFC 7541 §5.2. But a real server's response is
 * free to use it, and does in practice, so decoding it is required to read
 * back a real HEADERS frame (Phase 17.3). This file is decode-only; there
 * is no hpack_huffman_encode().
 *
 * The 257-entry canonical code table (256 symbols + EOS) below was not
 * hand-transcribed from RFC 7541 Appendix B: it was mechanically extracted
 * from the RFC's own published text with a small parsing script, and the
 * resulting table (and this decoder) were verified byte-for-byte against
 * the RFC's own worked Huffman examples in Appendix C.4.1/C.4.2 before
 * being committed. See docs/SECURITY.md, Step 17.2.1, for the full
 * methodology.
 *
 * Freestanding, no libc, matching the rest of this directory's convention. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Huffman-decode `inlen` bytes at `in` into `out` (capacity `outcap`),
 * writing the decoded length to `*outlen`. Returns 0 on success, or -1 if:
 *   - the decoded output would not fit in `outcap`;
 *   - a bit sequence longer than the longest valid code (30 bits) appears
 *     without matching any symbol (RFC 7541 §5.2: "as EOS ... MUST NOT be
 *     encoded", so a run that long can only mean corrupt/malicious input);
 *   - more than 7 padding bits remain after the last decoded symbol, or
 *     those padding bits are not all 1s (RFC 7541 §5.2: padding "MUST be
 *     as if the EOS symbol were used", and EOS's own code is 30 one-bits,
 *     so any valid short padding is a prefix of nothing but 1s). */
int hpack_huffman_decode(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t outcap, size_t *outlen);
