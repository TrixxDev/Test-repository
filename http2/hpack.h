/* HPACK header compression (RFC 7541) — encode side only, static table
 * only — Phase 17.1.3.
 *
 * Just enough to build a real, RFC-correct HTTP/2 request header block:
 * prefixed-integer encoding (§5.1), string literals (§5.2, always with the
 * Huffman bit clear -- Huffman is optional for a sender, RFC 7541 §5.2, and
 * decoding it is a decode-side problem this phase doesn't have), the
 * "Indexed Header Field" representation (§6.1) for a name+value pair that
 * matches a static table entry exactly, and "Literal Header Field without
 * Indexing" (§6.2.2) for everything else.
 *
 * Deliberately NOT "with incremental indexing" (§6.2.1): that representation
 * tells the peer's decoder to add the entry to ITS dynamic table, and this
 * client doesn't track a mirrored dynamic table of its own (that's Phase
 * 17.2) -- using it now would be a correctness trap waiting for a future
 * request reuse to walk into, not a missed optimization. No dynamic table
 * on this side means "without indexing" is the only representation that's
 * actually safe to send.
 *
 * Freestanding, no libc (matching frame.c/data.c/settings.c's own
 * convention in this directory): callers pass explicit lengths, never
 * NUL-terminated strings needing strlen(). */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Static table indices (RFC 7541 Appendix A) this client actually uses.
 * The table has 61 entries in total; only the ones this send-side encoder
 * needs are named here -- the decode side (17.2.2's hpack_table.c) has the
 * full table. */
#define HPACK_IDX_AUTHORITY      1   /* :authority (no value in the table) */
#define HPACK_IDX_METHOD_GET     2   /* :method: GET */
#define HPACK_IDX_METHOD_POST    3   /* :method: POST */
#define HPACK_IDX_PATH_ROOT      4   /* :path: / */
#define HPACK_IDX_SCHEME_HTTPS   7   /* :scheme: https */
#define HPACK_IDX_CONTENT_LENGTH 28  /* content-length (no value in the table) */
#define HPACK_IDX_CONTENT_TYPE   31  /* content-type (no value in the table) */
#define HPACK_IDX_USER_AGENT    58   /* user-agent (no value in the table) */

/* Append one HPACK prefixed integer (RFC 7541 §5.1) to `out` at `*pos`
 * (capped at `cap`). `prefix_bits` is how many low bits of the first byte
 * hold the integer (the rest of that byte -- `flag_bits`, already shifted
 * into its final position -- is the representation-type marker the caller
 * ORs in). Returns 0, or -1 on capacity error. */
int hpack_put_int(uint8_t *out, size_t cap, size_t *pos,
                  int prefix_bits, uint8_t flag_bits, uint32_t value);

/* Append one HPACK string literal (RFC 7541 §5.2): a 7-bit-prefixed length
 * (Huffman bit always clear) followed by `len` raw bytes. Returns 0, or -1
 * on capacity error. */
int hpack_put_string(uint8_t *out, size_t cap, size_t *pos, const char *s, size_t len);

/* Append one "Indexed Header Field" representation (RFC 7541 §6.1): both
 * name and value come from static table entry `index`. Returns 0, or -1 on
 * capacity error. */
int hpack_put_indexed(uint8_t *out, size_t cap, size_t *pos, unsigned index);

/* Append one "Literal Header Field without Indexing" representation (RFC
 * 7541 §6.2.2) whose NAME is static table entry `name_index` and whose
 * VALUE is the literal string `value`/`value_len`. Returns 0, or -1 on
 * capacity error. */
int hpack_put_literal_indexed_name(uint8_t *out, size_t cap, size_t *pos,
                                   unsigned name_index, const char *value, size_t value_len);
