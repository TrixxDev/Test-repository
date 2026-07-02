/* HPACK header-block decoding (RFC 7541 §5/§6) — decode side — Phase 17.2.2.
 *
 * Completes the HPACK decoder: RFC 7541 §5.1's prefixed-integer decode and
 * §5.2's string-literal decode (raw or Huffman, via huffman.c), dispatched
 * across every §6 representation -- Indexed Header Field (§6.1), Literal
 * Header Field with Incremental Indexing (§6.2.1, the only representation
 * that grows the dynamic table), Literal Header Field without Indexing
 * (§6.2.2), Literal Header Field Never Indexed (§6.2.3, decoded identically
 * to §6.2.2 -- Aurora isn't a proxy re-encoding what it received, so the
 * two representations' only real-world difference doesn't apply here), and
 * Dynamic Table Size Update (§6.3).
 *
 * Freestanding, no libc, matching the rest of this directory's convention. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "hpack_table.h"

/* One decoded header field: `name`/`value` point into the caller-supplied
 * `scratch` buffer passed to hpack_decode_headers() (not into `in` --
 * Huffman-coded strings can't be decoded in place), valid until that
 * buffer is next reused. */
typedef struct {
    const uint8_t *name; size_t name_len;
    const uint8_t *value; size_t value_len;
} hpack_header_field;

/* Decode one full HPACK header block -- the concatenated payload of a
 * HEADERS frame (plus any CONTINUATION frames, though Aurora neither sends
 * nor expects one yet) -- into `out` (capacity `out_cap` fields), applying
 * every representation's dynamic-table side effect (insertion, eviction,
 * size update) against `table`. Every decoded string (literal or
 * Huffman-coded alike) is copied into `scratch` (capacity `scratch_cap`).
 *
 * Returns 0 and sets *out_count (and *scratch_used, how much of `scratch`
 * was consumed) on success. Returns -1 on any malformed input: a truncated
 * or overflowing prefixed integer, an indexed field or an indexed literal
 * name whose index isn't currently live (RFC 7541 §6.1's mandatory
 * decoding error), a string literal whose declared length runs past `in`,
 * a Huffman decode failure, a Dynamic Table Size Update past what this
 * decoder could ever have advertised, more distinct header fields than
 * `out_cap`, or `scratch` running out of room.
 *
 * HPACK's tables are a shared compression *context* carried across the
 * whole connection, not just one header block -- a malformed block leaves
 * `table` in a state a real peer's own encoder never would have produced,
 * so every subsequent block on this connection is now unverifiable too.
 * On failure the caller MUST treat this as fatal for the whole connection
 * (closing it), not retry just the one request/response; `table`'s side
 * effects up to the point of failure are deliberately not rolled back,
 * matching what a real decoder would do anyway -- there's no safe context
 * to roll back TO once trust in it is gone. */
int hpack_decode_headers(const uint8_t *in, size_t in_len,
                         hpack_dyn_table *table,
                         hpack_header_field *out, size_t out_cap, size_t *out_count,
                         uint8_t *scratch, size_t scratch_cap, size_t *scratch_used);
