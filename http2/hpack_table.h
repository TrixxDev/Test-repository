/* HPACK header tables (RFC 7541 §2.3) — decode side — Phase 17.2.2.
 *
 * Two tables, one unified index space (RFC 7541 §2.3.3): the STATIC table
 * (Appendix A, 61 fixed entries, indices 1-61) and a DYNAMIC table (§2.3.2,
 * indices 62+, most-recently-inserted first) that this decoder builds up
 * as it processes a peer's HPACK-compressed header blocks.
 *
 * This mirrors what a real peer's *encoder* is doing on its own side of
 * the connection -- but only in the receive direction. Aurora's own
 * encoder (hpack.c, Phase 17.1.3) deliberately never uses incremental
 * indexing, so it never asks a peer's decoder to grow a table that would
 * need to be tracked on Aurora's send side; nothing here changes that.
 * RFC 7541 §2.3.2 is explicit that the two directions' dynamic tables are
 * entirely independent, so decode-side tracking carries none of the
 * synchronization risk that indexing on Aurora's own send side would.
 *
 * Freestanding, no libc, matching the rest of this directory's convention:
 * a fixed-capacity byte arena backs the dynamic table instead of malloc'd
 * per-entry storage (this directory's large-structure convention is
 * `static` globals sized for the worst case, never a dynamic allocator). */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Hard capacity of the dynamic table's backing byte arena. RFC 7541 §4.2:
 * a peer's dynamic table can never legally exceed the SETTINGS_HEADER_
 * TABLE_SIZE the *decoder* (Aurora) has advertised. Aurora's own SETTINGS
 * frame is currently empty (Phase 17.1.1), so the RFC 7540 §6.5.2 default
 * value -- 4096 -- is what's actually in effect; sizing the arena to that
 * exact value means no legally-behaving peer can ever be asked to store
 * more than this decoder can hold. */
#define HPACK_DYN_ARENA_SIZE 4096

/* RFC 7541 §4.1: every entry costs at least 32 bytes of accounting
 * overhead even with a zero-length name and value, so no more than
 * ARENA_SIZE/32 entries can ever coexist under any legal max_size -- this
 * is a hard, provable upper bound, not a guess. */
#define HPACK_DYN_MAX_ENTRIES (HPACK_DYN_ARENA_SIZE / 32)

typedef struct {
    size_t name_off, name_len;
    size_t value_off, value_len;
} hpack_dyn_entry;

typedef struct {
    uint8_t arena[HPACK_DYN_ARENA_SIZE];
    hpack_dyn_entry entries[HPACK_DYN_MAX_ENTRIES];  /* [0] = most recent (index 62) */
    int count;
    size_t used;       /* bytes of arena[] actually occupied (raw name+value bytes only) */
    size_t size;        /* RFC 7541 §4.1 accounting size: used + 32*count */
    size_t max_size;    /* current negotiated limit; changeable via a Dynamic Table Size Update */
} hpack_dyn_table;

/* Initialize (or reset) `t`, empty, with the given starting max size.
 * `max_size` must be <= HPACK_DYN_ARENA_SIZE -- this is a trusted,
 * locally-chosen starting point (what Aurora itself would advertise),
 * not peer-controlled input; use hpack_table_set_max_size() for a value
 * that came off the wire. */
void hpack_table_init(hpack_dyn_table *t, size_t max_size);

/* RFC 7541 §6.3: apply a Dynamic Table Size Update -- changes max_size,
 * evicting existing entries (oldest first) as needed to fit. Returns 0, or
 * -1 if `new_max_size` exceeds HPACK_DYN_ARENA_SIZE (a peer claiming a
 * table size this decoder never advertised being able to support -- a
 * protocol violation, not something to silently clamp). */
int hpack_table_set_max_size(hpack_dyn_table *t, size_t new_max_size);

/* RFC 7541 §6.2.1's side effect: insert a new entry as the most recent
 * (index 62), evicting the oldest entries as needed to make room under
 * `t->max_size`. Per RFC 7541 §4.4, if the new entry's own size (name_len
 * + value_len + 32) exceeds max_size even after the table is fully
 * emptied, the new entry is simply not stored -- this only affects
 * whether a *future* reference to it by index would resolve; the caller
 * already has the decoded name/value independently of this call. */
void hpack_table_insert(hpack_dyn_table *t, const uint8_t *name, size_t name_len,
                        const uint8_t *value, size_t value_len);

/* Resolve `index` (RFC 7541 §2.3.3's unified space: 1-61 static, 62+
 * dynamic) to its name/value. On success returns 0 and sets *name,
 * *name_len, *value, and *value_len (a static entry with no fixed value,
 * or any dynamic entry, always has a value -- dynamic entries are only
 * ever inserted with one; *value_len is 0 for the handful of static
 * entries RFC 7541 Appendix A leaves empty). Returns -1 for index 0 or any index
 * past the last currently-live entry (RFC 7541 §6.1: a decoder "MUST
 * treat" this "as a decoding error"). */
int hpack_table_get(const hpack_dyn_table *t, unsigned index,
                    const uint8_t **name, size_t *name_len,
                    const uint8_t **value, size_t *value_len);
