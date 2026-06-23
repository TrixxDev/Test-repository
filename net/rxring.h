/* Fixed-size byte ring buffer for a TCP receive queue.
 *
 * Why this exists: the previous per-connection rx buffer used a write cursor that
 * was never rewound when the application read, so a connection could only ever
 * absorb TCP_RX_CAP bytes *over its entire lifetime* — a real transport defect,
 * not just a size limit. A ring frees space as the application drains, so the
 * window genuinely reopens and the connection lives indefinitely.
 *
 * It is a pure data structure: it knows nothing about TCP, sequence numbers, or
 * windows. The caller decides the accept/drop *policy* (e.g. all-or-nothing per
 * segment); this only stores and returns bytes. Freestanding by construction —
 * only <stdint.h>/<stddef.h>, explicit byte copies, no memcpy — so the very same
 * source compiles into the kernel and into the host test. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* 16 KiB: comfortably above one max TLS record on the wire (2^14 + 256) and a
 * few-KiB certificate chain, so realistic traffic rarely hits backpressure.
 * Fixed, not dynamic — Aurora does not page the kernel heap for this. */
#define RX_RING_CAP 16384

typedef struct {
    uint8_t  buf[RX_RING_CAP];
    unsigned head;      /* index of the oldest stored byte */
    unsigned count;     /* bytes currently stored (0..RX_RING_CAP) */
} rxring;

void     rxring_init(rxring *r);

/* Append up to `len` bytes, never more than the free space. Returns the number
 * actually stored (< len means the ring filled). The caller that wants
 * all-or-nothing checks rxring_free() >= len first. */
unsigned rxring_push(rxring *r, const uint8_t *data, unsigned len);

/* Remove up to `cap` of the oldest bytes into `out` (FIFO). Returns the number
 * copied (0 if empty). */
unsigned rxring_pop(rxring *r, uint8_t *out, unsigned cap);

static inline unsigned rxring_used(const rxring *r) { return r->count; }
static inline unsigned rxring_free(const rxring *r) { return RX_RING_CAP - r->count; }
