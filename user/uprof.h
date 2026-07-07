/* Phase 18.5.3: userspace profiling counters for the TLS/HTTP2 client stack
 * (crypto/tls/http2 -- see kernel/prof.h for the analogous kernel-side
 * counters from 18.5.2). One shared global, incremented directly by each
 * instrumented call site, same flat-struct style as kernel/prof.h and
 * net/tcp.c's own `stats`.
 *
 * AEAD is measured as one combined ChaCha20+Poly1305 number, not split into
 * two: crypto/chacha20poly1305.c (and chacha20.c/poly1305.c beneath it) are
 * deliberately "portable + freestanding... no OS calls" (see their own
 * header comments) and stay that way here -- this clock is an OS-coupled
 * dependency (a syscall on real hardware) that crypto/ itself never gets
 * to see. The timing wraps tls/record.c's tls_record_seal()/open() instead,
 * one layer up, where such a dependency is already normal. */
#pragma once
#include <stdint.h>

struct client_prof {
    unsigned aead_seal_calls, aead_seal_us, aead_seal_bytes;
    unsigned aead_open_calls, aead_open_us, aead_open_bytes;
    unsigned hpack_encode_calls, hpack_encode_us, hpack_encode_bytes;
    unsigned hpack_decode_calls, hpack_decode_us, hpack_decode_bytes;
    unsigned h2_frame_calls, h2_frame_us, h2_frame_bytes;
};

extern struct client_prof g_cprof;

/* Monotonic microsecond clock. Real userspace binaries link
 * user/uprof_clock.c (calls the perf_us() syscall); each host test tool
 * that links this instrumented code directly (tools/tls_test.c,
 * tools/tls_live_test.c, tools/h2_test.c) provides its own simple
 * incrementing stub instead -- exactly the same "externally supplied,
 * stubbed on the host" contract net/tcp.c's perf_now_us()/net_now_ms()
 * already use for its own host tests. */
uint64_t cprof_now_us(void);
