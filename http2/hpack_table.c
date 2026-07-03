/* HPACK header tables — see hpack_table.h. */
#include "hpack_table.h"

/* The static table just below is RFC 7541 Appendix A verbatim (mechanically
 * extracted from the RFC's own text, not hand-transcribed -- see the
 * methodology note in huffman.h/docs/SECURITY.md for why that matters at
 * this scale). Each string's length is computed by the compiler via
 * `sizeof(x) - 1`, not hand-counted -- the exact class of mistake that
 * bit a hand-counted user-agent length in Phase 17.1.3. */
typedef struct {
    const char *name; size_t name_len;
    const char *value; size_t value_len;   /* value/value_len are 0 when Appendix A leaves this entry's value empty */
} hpack_static_entry;

/* Generated directly from RFC 7541 Appendix A -- do not hand-edit. */
#define S(x) x, sizeof(x) - 1

static const hpack_static_entry hpack_static_table[61] = {
    { S(":authority"), 0, 0 },  /* 1 */
    { S(":method"), S("GET") },  /* 2 */
    { S(":method"), S("POST") },  /* 3 */
    { S(":path"), S("/") },  /* 4 */
    { S(":path"), S("/index.html") },  /* 5 */
    { S(":scheme"), S("http") },  /* 6 */
    { S(":scheme"), S("https") },  /* 7 */
    { S(":status"), S("200") },  /* 8 */
    { S(":status"), S("204") },  /* 9 */
    { S(":status"), S("206") },  /* 10 */
    { S(":status"), S("304") },  /* 11 */
    { S(":status"), S("400") },  /* 12 */
    { S(":status"), S("404") },  /* 13 */
    { S(":status"), S("500") },  /* 14 */
    { S("accept-charset"), 0, 0 },  /* 15 */
    { S("accept-encoding"), S("gzip, deflate") },  /* 16 */
    { S("accept-language"), 0, 0 },  /* 17 */
    { S("accept-ranges"), 0, 0 },  /* 18 */
    { S("accept"), 0, 0 },  /* 19 */
    { S("access-control-allow-origin"), 0, 0 },  /* 20 */
    { S("age"), 0, 0 },  /* 21 */
    { S("allow"), 0, 0 },  /* 22 */
    { S("authorization"), 0, 0 },  /* 23 */
    { S("cache-control"), 0, 0 },  /* 24 */
    { S("content-disposition"), 0, 0 },  /* 25 */
    { S("content-encoding"), 0, 0 },  /* 26 */
    { S("content-language"), 0, 0 },  /* 27 */
    { S("content-length"), 0, 0 },  /* 28 */
    { S("content-location"), 0, 0 },  /* 29 */
    { S("content-range"), 0, 0 },  /* 30 */
    { S("content-type"), 0, 0 },  /* 31 */
    { S("cookie"), 0, 0 },  /* 32 */
    { S("date"), 0, 0 },  /* 33 */
    { S("etag"), 0, 0 },  /* 34 */
    { S("expect"), 0, 0 },  /* 35 */
    { S("expires"), 0, 0 },  /* 36 */
    { S("from"), 0, 0 },  /* 37 */
    { S("host"), 0, 0 },  /* 38 */
    { S("if-match"), 0, 0 },  /* 39 */
    { S("if-modified-since"), 0, 0 },  /* 40 */
    { S("if-none-match"), 0, 0 },  /* 41 */
    { S("if-range"), 0, 0 },  /* 42 */
    { S("if-unmodified-since"), 0, 0 },  /* 43 */
    { S("last-modified"), 0, 0 },  /* 44 */
    { S("link"), 0, 0 },  /* 45 */
    { S("location"), 0, 0 },  /* 46 */
    { S("max-forwards"), 0, 0 },  /* 47 */
    { S("proxy-authenticate"), 0, 0 },  /* 48 */
    { S("proxy-authorization"), 0, 0 },  /* 49 */
    { S("range"), 0, 0 },  /* 50 */
    { S("referer"), 0, 0 },  /* 51 */
    { S("refresh"), 0, 0 },  /* 52 */
    { S("retry-after"), 0, 0 },  /* 53 */
    { S("server"), 0, 0 },  /* 54 */
    { S("set-cookie"), 0, 0 },  /* 55 */
    { S("strict-transport-security"), 0, 0 },  /* 56 */
    { S("transfer-encoding"), 0, 0 },  /* 57 */
    { S("user-agent"), 0, 0 },  /* 58 */
    { S("vary"), 0, 0 },  /* 59 */
    { S("via"), 0, 0 },  /* 60 */
    { S("www-authenticate"), 0, 0 },  /* 61 */
};

static void hpack_table_evict_oldest(hpack_dyn_table *t)
{
    /* Caller guarantees t->count > 0. Invariant maintained by every
     * insert/evict: the currently-oldest live entry's bytes always start
     * at arena offset 0 (new entries append after the current tail; the
     * only way bytes are removed is evicting the entry at offset 0 and
     * compacting everything after it down to close the gap), so evicting
     * "the entry at the highest entries[] index" and "the bytes at the
     * front of arena[]" are the same operation. */
    int last = t->count - 1;
    hpack_dyn_entry *e = &t->entries[last];
    size_t freed = e->name_len + e->value_len;
    size_t entry_size = freed + 32;

    for (size_t i = freed; i < t->used; i++) t->arena[i - freed] = t->arena[i];
    t->used -= freed;
    for (int i = 0; i < last; i++) {
        t->entries[i].name_off -= freed;
        t->entries[i].value_off -= freed;
    }
    t->count--;
    t->size -= entry_size;
}

void hpack_table_init(hpack_dyn_table *t, size_t max_size)
{
    t->count = 0;
    t->used = 0;
    t->size = 0;
    t->max_size = max_size;
}

int hpack_table_set_max_size(hpack_dyn_table *t, size_t new_max_size)
{
    if (new_max_size > HPACK_DYN_ARENA_SIZE) return -1;
    t->max_size = new_max_size;
    while (t->count > 0 && t->size > t->max_size) hpack_table_evict_oldest(t);
    return 0;
}

void hpack_table_insert(hpack_dyn_table *t, const uint8_t *name, size_t name_len,
                        const uint8_t *value, size_t value_len)
{
    size_t new_size = name_len + value_len + 32;

    while (t->count > 0 && t->size + new_size > t->max_size) hpack_table_evict_oldest(t);

    if (new_size > t->max_size) {
        /* RFC 7541 §4.4: the table is now empty (the loop above emptied
         * it trying to make room) and the new entry itself still doesn't
         * fit -- it is simply not stored. */
        return;
    }
    if (t->count >= HPACK_DYN_MAX_ENTRIES) hpack_table_evict_oldest(t);   /* defensive; see hpack_table.h */

    for (int i = t->count; i > 0; i--) t->entries[i] = t->entries[i - 1];

    size_t name_off = t->used;
    for (size_t i = 0; i < name_len; i++) t->arena[t->used++] = name[i];
    size_t value_off = t->used;
    for (size_t i = 0; i < value_len; i++) t->arena[t->used++] = value[i];

    t->entries[0].name_off = name_off;
    t->entries[0].name_len = name_len;
    t->entries[0].value_off = value_off;
    t->entries[0].value_len = value_len;
    t->count++;
    t->size += new_size;
}

int hpack_table_get(const hpack_dyn_table *t, unsigned index,
                    const uint8_t **name, size_t *name_len,
                    const uint8_t **value, size_t *value_len)
{
    if (index == 0) return -1;
    if (index <= 61) {
        const hpack_static_entry *e = &hpack_static_table[index - 1];
        *name = (const uint8_t *)e->name; *name_len = e->name_len;
        *value = (const uint8_t *)e->value; *value_len = e->value_len;
        return 0;
    }
    unsigned dyn_index = index - 62;
    /* Phase 17.5.1 fuzzing finding: comparing against a *signed* cast of
     * t->count let an index whose dyn_index overflowed INT_MAX (any
     * legitimately-encoded HPACK integer, RFC 7541 §5.1, up to UINT32_MAX
     * is "valid" as far as hpack_get_int() is concerned) turn negative and
     * silently pass this bounds check, corrupting `t->entries[dyn_index]`
     * into a massive out-of-bounds array access. t->count is always
     * non-negative (0..HPACK_DYN_MAX_ENTRIES), so comparing entirely in
     * unsigned arithmetic is both correct and just as cheap. */
    if (dyn_index >= (unsigned)t->count) return -1;
    const hpack_dyn_entry *e = &t->entries[dyn_index];
    *name = t->arena + e->name_off; *name_len = e->name_len;
    *value = t->arena + e->value_off; *value_len = e->value_len;
    return 0;
}
