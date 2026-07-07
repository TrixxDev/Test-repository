/* High-resolution monotonic clock (RDTSC, calibrated against the PIT).
 *
 * The PIT only gives 10 ms ticks — useless for measuring a ~1 ms compose. This
 * exposes a microsecond clock for profiling the compositor (and, later, network
 * timeouts). On a CPU without RDTSC it transparently falls back to the PIT. */
#pragma once
#include <stdint.h>

/* Calibrate the TSC once at boot, AFTER the PIT is installed and interrupts are
 * on (it busy-waits ~100 ms on PIT ticks). Safe to call before the scheduler. */
void     perf_calibrate(void);

/* Microseconds since perf_calibrate(). Monotonic. */
uint64_t perf_now_us(void);

/* Diagnostics for the perf overlay / boot log. */
int      perf_have_tsc(void);        /* 1 = calibrated TSC, 0 = PIT fallback */
int      perf_tsc_invariant(void);   /* 1 = CPUID reports an invariant TSC   */
uint32_t perf_tsc_mhz(void);         /* calibrated TSC rate (MHz), 0 if PIT   */
