/* HPACK header-block decoding — see hpack_decode.h. */
#include "hpack_decode.h"
#include "huffman.h"

/* RFC 7541 §5.1. `prefix_bits` low bits of the byte at *pos hold the
 * value's start (the caller has already dispatched on the representation
 * bits above that, so they're simply masked off here); the rest of the
 * function is the RFC's own decode algorithm, verbatim. */
static int hpack_get_int(const uint8_t *in, size_t in_len, size_t *pos,
                         int prefix_bits, uint32_t *value)
{
    if (*pos >= in_len) return -1;
    uint32_t max_prefix = (1u << prefix_bits) - 1u;
    uint32_t v = in[*pos] & max_prefix;
    (*pos)++;
    if (v < max_prefix) { *value = v; return 0; }

    uint32_t m = 0;
    for (;;) {
        if (*pos >= in_len) return -1;
        uint8_t b = in[(*pos)++];
        if (m >= 32 || (uint64_t)v + ((uint64_t)(b & 0x7f) << m) > 0xFFFFFFFFull) return -1;
        v += (uint32_t)(b & 0x7f) << m;
        if ((b & 0x80) == 0) { *value = v; return 0; }
        m += 7;
    }
}

/* Copy `len` bytes from `src` into `scratch` at `*spos`, advancing it.
 * Every byte range this decoder ever hands back to a caller, or ever
 * passes to hpack_table_insert() as new table content, goes through this
 * -- including bytes resolved *from* the dynamic table itself (see the
 * dispatcher below for why that copy is not optional). */
static int hpack_copy_to_scratch(const uint8_t *src, size_t len,
                                 uint8_t *scratch, size_t scratch_cap, size_t *spos,
                                 const uint8_t **out, size_t *out_len)
{
    if (*spos + len > scratch_cap) return -1;
    *out = scratch + *spos;
    for (size_t i = 0; i < len; i++) scratch[(*spos)++] = src[i];
    *out_len = len;
    return 0;
}

/* RFC 7541 §5.2: a 1-bit Huffman flag, a 7-bit-prefixed length, then that
 * many raw bytes -- Huffman-decoded into `scratch` if the flag is set,
 * copied as-is otherwise. Either way the result lands in `scratch` (never
 * a pointer back into `in`), since Huffman decoding can't happen in place. */
static int hpack_get_string(const uint8_t *in, size_t in_len, size_t *pos,
                            uint8_t *scratch, size_t scratch_cap, size_t *spos,
                            const uint8_t **out, size_t *out_len)
{
    if (*pos >= in_len) return -1;
    int huffman = (in[*pos] & 0x80) != 0;
    uint32_t len;
    if (hpack_get_int(in, in_len, pos, 7, &len) != 0) return -1;
    if (*pos + len > in_len) return -1;
    const uint8_t *raw = in + *pos;
    *pos += len;

    if (!huffman) return hpack_copy_to_scratch(raw, len, scratch, scratch_cap, spos, out, out_len);

    size_t decoded_len;
    if (hpack_huffman_decode(raw, len, scratch + *spos, scratch_cap - *spos, &decoded_len) != 0) return -1;
    *out = scratch + *spos;
    *spos += decoded_len;
    *out_len = decoded_len;
    return 0;
}

/* Resolve an indexed name (or decode a literal one, if `index` is 0) into
 * `scratch` -- NEVER a raw pointer into `table`'s own dynamic-table arena.
 * That matters for a subtle reason: a *later* representation in the same
 * header block (e.g. a Literal Header Field with Incremental Indexing
 * that needs to evict old entries to make room) can compact and shift
 * that arena out from under an earlier representation's already-decoded
 * name/value -- RFC 7541 Appendix C.5.3 is a real, RFC-published example
 * where exactly this happens (a `cache-control` entry referenced early in
 * the block is evicted later in the very same block). Copying resolved
 * bytes into `scratch` immediately, before anything else in the block can
 * run, keeps every decoded field's lifetime independent of the table's. */
static int hpack_resolve_name(hpack_dyn_table *table, unsigned index,
                              uint8_t *scratch, size_t scratch_cap, size_t *spos,
                              const uint8_t **name, size_t *name_len)
{
    const uint8_t *rn, *rv; size_t rnl, rvl;
    if (hpack_table_get(table, index, &rn, &rnl, &rv, &rvl) != 0) return -1;
    (void)rv; (void)rvl;
    return hpack_copy_to_scratch(rn, rnl, scratch, scratch_cap, spos, name, name_len);
}

/* Shared tail for every §6.2.x literal representation: an indexed-or-
 * literal name (0 = literal follows; nonzero = resolved from `table`, via
 * hpack_resolve_name() above), always followed by a literal value. */
static int hpack_get_literal(const uint8_t *in, size_t in_len, size_t *pos, int prefix_bits,
                             hpack_dyn_table *table, uint8_t *scratch, size_t scratch_cap, size_t *spos,
                             const uint8_t **name, size_t *name_len,
                             const uint8_t **value, size_t *value_len)
{
    uint32_t name_index;
    if (hpack_get_int(in, in_len, pos, prefix_bits, &name_index) != 0) return -1;

    if (name_index == 0) {
        if (hpack_get_string(in, in_len, pos, scratch, scratch_cap, spos, name, name_len) != 0) return -1;
    } else {
        if (hpack_resolve_name(table, name_index, scratch, scratch_cap, spos, name, name_len) != 0) return -1;
    }

    return hpack_get_string(in, in_len, pos, scratch, scratch_cap, spos, value, value_len);
}

int hpack_decode_headers(const uint8_t *in, size_t in_len, hpack_dyn_table *table,
                         hpack_header_field *out, size_t out_cap, size_t *out_count,
                         uint8_t *scratch, size_t scratch_cap, size_t *scratch_used)
{
    size_t pos = 0, spos = 0, n = 0;

    while (pos < in_len) {
        uint8_t first = in[pos];

        if (first & 0x80) {
            /* Indexed Header Field -- RFC 7541 §6.1: "1" + a 7-bit-prefixed
             * index. Both name and value are copied into `scratch` (see
             * hpack_resolve_name()'s comment for why that's required, not
             * just tidy, when the index resolves into the dynamic table). */
            uint32_t index;
            if (hpack_get_int(in, in_len, &pos, 7, &index) != 0) return -1;
            const uint8_t *rn, *rv; size_t rnl, rvl;
            if (hpack_table_get(table, index, &rn, &rnl, &rv, &rvl) != 0) return -1;
            if (n >= out_cap) return -1;
            if (hpack_copy_to_scratch(rn, rnl, scratch, scratch_cap, &spos, &out[n].name, &out[n].name_len) != 0) return -1;
            if (hpack_copy_to_scratch(rv, rvl, scratch, scratch_cap, &spos, &out[n].value, &out[n].value_len) != 0) return -1;
            n++;
        } else if (first & 0x40) {
            /* Literal Header Field with Incremental Indexing -- RFC 7541
             * §6.2.1: "01" + a 6-bit-prefixed name index/0. Adds the
             * decoded field to the dynamic table. */
            const uint8_t *name, *value; size_t name_len, value_len;
            if (hpack_get_literal(in, in_len, &pos, 6, table, scratch, scratch_cap, &spos,
                                  &name, &name_len, &value, &value_len) != 0) return -1;
            hpack_table_insert(table, name, name_len, value, value_len);
            if (n >= out_cap) return -1;
            out[n].name = name; out[n].name_len = name_len;
            out[n].value = value; out[n].value_len = value_len;
            n++;
        } else if ((first & 0xE0) == 0x20) {
            /* Dynamic Table Size Update -- RFC 7541 §6.3: "001" + a 5-bit-prefixed size. */
            uint32_t new_size;
            if (hpack_get_int(in, in_len, &pos, 5, &new_size) != 0) return -1;
            if (hpack_table_set_max_size(table, new_size) != 0) return -1;
        } else {
            /* Literal Header Field without Indexing (§6.2.2, "0000") or
             * Never Indexed (§6.2.3, "0001") -- both use a 4-bit prefix
             * and neither touches the dynamic table; nothing here needs
             * to tell them apart (see hpack_decode.h). */
            const uint8_t *name, *value; size_t name_len, value_len;
            if (hpack_get_literal(in, in_len, &pos, 4, table, scratch, scratch_cap, &spos,
                                  &name, &name_len, &value, &value_len) != 0) return -1;
            if (n >= out_cap) return -1;
            out[n].name = name; out[n].name_len = name_len;
            out[n].value = value; out[n].value_len = value_len;
            n++;
        }
    }

    *out_count = n;
    *scratch_used = spos;
    return 0;
}
