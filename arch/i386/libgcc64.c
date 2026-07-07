/* 64-bit unsigned divide/modulo for the freestanding kernel.
 *
 * `-nostdlib` means no libgcc, but the compiler still lowers any 64-bit `/` or `%`
 * (e.g. the TSC->microsecond conversion in perf.c) into calls to these symbols.
 * A plain binary long division — not fast, but 64-bit division is rare in the
 * kernel (perf timing, future network timeouts), so clarity wins. */
#include <stdint.h>

static uint64_t udivmod64(uint64_t num, uint64_t den, uint64_t *rem)
{
    if (den == 0) {                 /* avoid a #DE; mirror libgcc's "return garbage" */
        if (rem) *rem = 0;
        return ~0ULL;
    }
    uint64_t quot = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((num >> i) & 1ULL);
        if (r >= den) {
            r -= den;
            quot |= (uint64_t)1 << i;
        }
    }
    if (rem) *rem = r;
    return quot;
}

uint64_t __udivdi3(uint64_t a, uint64_t b) { return udivmod64(a, b, 0); }

uint64_t __umoddi3(uint64_t a, uint64_t b) { uint64_t r; udivmod64(a, b, &r); return r; }
