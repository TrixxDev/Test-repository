/* Phase 18.5: host-side throughput benchmark for the crypto/ primitives that
 * sit on every byte of an HTTPS response (TLS_CHACHA20_POLY1305_SHA256 is the
 * only cipher suite Aurora speaks). Not a correctness test -- tools/crypto_test.c
 * already proves that against RFC 8439 vectors -- this only measures MB/s, so a
 * change can be justified with a number instead of "should be faster." */
#include "chacha20.h"
#include "chacha20poly1305.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define BUF_LEN   (1u << 20)      /* 1 MiB, comparable to a large HTTP response */
#define ITERS     200             /* ~200 MiB total, enough to average out noise */

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint8_t buf_in[BUF_LEN];
static uint8_t buf_out[BUF_LEN];
static uint8_t tag[16];

int main(void)
{
    uint8_t key[32], nonce[12], aad[13];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 7);
    for (int i = 0; i < 13; i++) aad[i] = (uint8_t)(i * 3);
    for (unsigned i = 0; i < BUF_LEN; i++) buf_in[i] = (uint8_t)(i * 31 + 1);

    /* chacha20_xor alone -- the raw stream-cipher hot loop. */
    {
        chacha20_ctx c;
        chacha20_init(&c, key, nonce, 1);
        double t0 = now_s();
        for (int i = 0; i < ITERS; i++)
            chacha20_xor(&c, buf_in, buf_out, BUF_LEN);
        double dt = now_s() - t0;
        double mb = (double)BUF_LEN * ITERS / (1024.0 * 1024.0);
        printf("chacha20_xor:            %8.1f MiB in %6.3fs  =  %8.1f MiB/s\n",
               mb, dt, mb / dt);
    }

    /* Full AEAD seal (chacha20_xor + poly1305 over aad+ct+lengths) -- what a
     * real TLS record actually costs, not just the cipher in isolation. */
    {
        double t0 = now_s();
        for (int i = 0; i < ITERS; i++)
            chacha20poly1305_seal(buf_out, tag, key, nonce, aad, sizeof(aad),
                                  buf_in, BUF_LEN);
        double dt = now_s() - t0;
        double mb = (double)BUF_LEN * ITERS / (1024.0 * 1024.0);
        printf("chacha20poly1305_seal:   %8.1f MiB in %6.3fs  =  %8.1f MiB/s\n",
               mb, dt, mb / dt);
    }

    return 0;
}
