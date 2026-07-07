/* Fixed-size byte ring buffer — see rxring.h. */
#include "rxring.h"

void rxring_init(rxring *r)
{
    r->head = 0;
    r->count = 0;
}

unsigned rxring_push(rxring *r, const uint8_t *data, unsigned len)
{
    unsigned freeb = RX_RING_CAP - r->count;
    unsigned n = len < freeb ? len : freeb;

    unsigned tail = r->head + r->count;        /* one past the newest byte */
    if (tail >= RX_RING_CAP) tail -= RX_RING_CAP;

    for (unsigned i = 0; i < n; i++) {
        r->buf[tail] = data[i];
        if (++tail == RX_RING_CAP) tail = 0;   /* wrap */
    }
    r->count += n;
    return n;
}

unsigned rxring_pop(rxring *r, uint8_t *out, unsigned cap)
{
    unsigned n = r->count < cap ? r->count : cap;

    for (unsigned i = 0; i < n; i++) {
        out[i] = r->buf[r->head];
        if (++r->head == RX_RING_CAP) r->head = 0;   /* wrap */
    }
    r->count -= n;
    return n;
}
