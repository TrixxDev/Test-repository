/* High-resolution clock — see perf.h. */
#include "perf.h"
#include "pit.h"
#include "kio.h"

static uint64_t boot_tsc;
static uint32_t tsc_per_us;     /* ticks per microsecond; 0 => PIT fallback */
static int      have_tsc;
static int      invariant;

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpuid(uint32_t leaf,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    __asm__ volatile("cpuid"
        : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
        : "a"(leaf), "c"(0));
}

static int cpu_has_tsc(void)
{
    uint32_t a, b, c, d;
    cpuid(1, &a, &b, &c, &d);
    return (d >> 4) & 1;                 /* EDX bit 4 = TSC */
}

static int cpu_tsc_invariant(void)
{
    uint32_t a, b, c, d;
    cpuid(0x80000000u, &a, &b, &c, &d);  /* highest extended leaf */
    if (a < 0x80000007u)
        return 0;
    cpuid(0x80000007u, &a, &b, &c, &d);
    return (d >> 8) & 1;                 /* EDX bit 8 = invariant TSC */
}

void perf_calibrate(void)
{
    if (!cpu_has_tsc()) {                /* ancient CPU: fall back to the PIT */
        have_tsc = 0;
        kprintf("[perf] no TSC; using PIT (10 ms) for timing\n");
        return;
    }
    invariant = cpu_tsc_invariant();

    /* Measure the TSC over exactly 10 PIT ticks (= 100 ms at 100 Hz). Aligning to
     * a tick edge first removes the start-phase error, so the window is a whole
     * number of ticks and the rate is accurate to well under 1%. The PIT IRQ must
     * be live; the scheduler hook isn't installed yet, so nothing preempts us. */
    uint32_t edge = pit_ticks();
    while (pit_ticks() == edge) { }      /* align to the next tick edge */
    uint32_t start = pit_ticks();
    uint64_t tsc0 = rdtsc();
    while (pit_ticks() - start < 10) { } /* 10 ticks = 100000 us */
    uint64_t dtsc = rdtsc() - tsc0;

    tsc_per_us = (uint32_t)(dtsc / 100000ULL);
    if (tsc_per_us == 0)
        tsc_per_us = 1;                  /* guard against a degenerate measurement */
    have_tsc = 1;
    boot_tsc = rdtsc();

    kprintf("[perf] TSC calibrated: %u MHz (invariant=%d)\n", tsc_per_us, invariant);
}

uint64_t perf_now_us(void)
{
    if (!have_tsc)
        return (uint64_t)pit_ticks() * 10000ULL;   /* PIT fallback: 10 ms steps */
    return (rdtsc() - boot_tsc) / tsc_per_us;
}

int      perf_have_tsc(void)      { return have_tsc; }
int      perf_tsc_invariant(void) { return invariant; }
uint32_t perf_tsc_mhz(void)       { return have_tsc ? tsc_per_us : 0; }
