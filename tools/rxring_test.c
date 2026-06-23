/* Host-side test for the TCP receive ring (net/rxring.c). Proves the data
 * structure that fixes the "8 KiB over the whole connection lifetime" transport
 * defect: space freed by reads is reused, wrap-around preserves FIFO order, and
 * far more bytes than the buffer size can flow through it. Pure data structure,
 * no TCP, no QEMU. Build/run: `make rxring-test`. */
#include <stdio.h>
#include <stdint.h>
#include "rxring.h"

static int failures;

static void check(const char *name, int ok)
{
    if (ok) { printf("  PASS  %s\n", name); }
    else    { printf("  FAIL  %s\n", name); failures++; }
}

/* Deterministic ramp so stale/misordered bytes are caught: buf[i] = base + i. */
static void fill(uint8_t *buf, unsigned n, unsigned base)
{
    for (unsigned i = 0; i < n; i++) buf[i] = (uint8_t)(base + i);
}
static int is_ramp(const uint8_t *buf, unsigned n, unsigned base)
{
    for (unsigned i = 0; i < n; i++)
        if (buf[i] != (uint8_t)(base + i)) return 0;
    return 1;
}

int main(void)
{
    printf("TCP receive ring (rxring):\n");
    static rxring r;
    static uint8_t in[RX_RING_CAP * 2];
    static uint8_t out[RX_RING_CAP * 2];

    /* 1. empty after init */
    rxring_init(&r);
    check("init: used 0, free CAP", rxring_used(&r) == 0 && rxring_free(&r) == RX_RING_CAP);

    /* 2. simple push/pop preserves bytes and FIFO order */
    fill(in, 100, 0);
    check("push 100 -> stored 100", rxring_push(&r, in, 100) == 100);
    check("after push: used 100", rxring_used(&r) == 100 && rxring_free(&r) == RX_RING_CAP - 100);
    check("pop 100 -> got 100", rxring_pop(&r, out, 100) == 100);
    check("pop 100: bytes match ramp", is_ramp(out, 100, 0));
    check("after drain: used 0", rxring_used(&r) == 0);

    /* 3. partial pop leaves the remainder in order (continuation, not restart) */
    rxring_init(&r);
    fill(in, 200, 7);
    rxring_push(&r, in, 200);
    check("partial pop 50 -> 50", rxring_pop(&r, out, 50) == 50);
    check("partial pop: first 50 match", is_ramp(out, 50, 7));
    check("after partial pop: used 150", rxring_used(&r) == 150);
    check("pop remaining 150 -> 150", rxring_pop(&r, out, 150) == 150);
    check("remaining 150 continue the ramp", is_ramp(out, 150, 7 + 50));

    /* 4. push past free space stores only what fits, drops the rest (the caller's
     * all-or-nothing policy lives in TCP; the ring just refuses to overflow) */
    rxring_init(&r);
    fill(in, RX_RING_CAP + 10, 0);
    check("push CAP+10 -> stored CAP", rxring_push(&r, in, RX_RING_CAP + 10) == RX_RING_CAP);
    check("after overfill: free 0", rxring_free(&r) == 0 && rxring_used(&r) == RX_RING_CAP);
    check("drain CAP -> CAP", rxring_pop(&r, out, RX_RING_CAP) == RX_RING_CAP);
    check("overfill kept the first CAP bytes", is_ramp(out, RX_RING_CAP, 0));

    /* 5. wrap + write: leave a tail, then push across the physical end */
    rxring_init(&r);
    fill(in, 6000, 11);
    rxring_push(&r, in, 6000);
    check("wrap: pop 5000 -> 5000", rxring_pop(&r, out, 5000) == 5000);
    check("wrap: first 5000 match A", is_ramp(out, 5000, 11));
    check("wrap: 1000 left", rxring_used(&r) == 1000);
    fill(in, 7000, 200);                    /* ramp B, distinct base */
    check("wrap: push 7000 across end -> 7000", rxring_push(&r, in, 7000) == 7000);
    check("wrap: used 8000", rxring_used(&r) == 8000);
    check("wrap: drain 8000 -> 8000", rxring_pop(&r, out, 8000) == 8000);
    check("wrap: tail is A[5000..]", is_ramp(out, 1000, 11 + 5000));
    check("wrap: then B[0..]", is_ramp(out + 1000, 7000, 200));

    /* 6. full buffer boundary: free hits exactly 0, one pop frees exactly 1 */
    rxring_init(&r);
    fill(in, RX_RING_CAP, 0);
    rxring_push(&r, in, RX_RING_CAP);
    check("full: free 0", rxring_free(&r) == 0);
    check("full: pop 1 -> 1", rxring_pop(&r, out, 1) == 1);
    check("full: free 1 after pop 1", rxring_free(&r) == 1);
    check("full: push 2 stores only 1", rxring_push(&r, in, 2) == 1);
    check("full: free 0 again", rxring_free(&r) == 0 && rxring_used(&r) == RX_RING_CAP);

    /* 7. long lifetime: push far more than CAP through the ring over many wraps.
     * This is the exact scenario the old write-cursor buffer choked on after one
     * bufferful; here ~640 KiB flows through 16 KiB and every cycle round-trips. */
    rxring_init(&r);
    int lifetime_ok = 1;
    for (unsigned cycle = 0; cycle < 10000; cycle++) {
        uint8_t blk[64];
        unsigned base = cycle * 7 + 1;      /* changes each cycle: catches stale data */
        fill(blk, 64, base);
        if (rxring_push(&r, blk, 64) != 64) { lifetime_ok = 0; break; }
        if (rxring_pop(&r, out, 64) != 64)  { lifetime_ok = 0; break; }
        if (!is_ramp(out, 64, base))         { lifetime_ok = 0; break; }
    }
    check("lifetime: 10000x push64/pop64 round-trip", lifetime_ok);
    check("lifetime: ends empty (used 0, free CAP)",
          rxring_used(&r) == 0 && rxring_free(&r) == RX_RING_CAP);

    if (failures == 0) printf("ALL PASS\n");
    else               printf("%d FAILURE(S)\n", failures);
    return failures ? 1 : 0;
}
