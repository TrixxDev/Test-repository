/* Host-side ECDSA-P384-SHA384 verification test, driven by the official Google
 * Wycheproof vectors (ecdsa_secp384r1_sha384, v1: 504 cases). The P-384 analogue
 * of the P-256 ecdsa-test: the negative cases (r/s = 0 or >= n, modified
 * hash/signature, malformed/over-long/leading-zero DER, points off-curve, edge
 * values near n) are where real implementations break. Build/run:
 * `make ecdsa384-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "ecdsa384.h"
#include "sha384.h"

#include "ecdsa_wycheproof384.inc"   /* wpcases[], WP_NCASES */

static int hexbytes(const char *h, uint8_t *out)
{
    int n = (int)strlen(h) / 2;
    for (int i = 0; i < n; i++) {
        int hi = h[i*2], lo = h[i*2+1];
        hi = (hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
        lo = (lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

int main(void)
{
    static uint8_t pub[128], msg[8192], sig[8192], hash[48];
    int fails = 0, valid_ok = 0, invalid_ok = 0;

    printf("ECDSA P-384 / SHA-384 — Wycheproof (%d vectors):\n", WP_NCASES);
    clock_t t0 = clock();
    for (int i = 0; i < WP_NCASES; i++) {
        const struct wpcase *c = &wpcases[i];
        int publen = hexbytes(c->pub, pub);
        int mlen = hexbytes(c->msg, msg);
        int slen = hexbytes(c->sig, sig);
        sha384(msg, (size_t)mlen, hash);

        int rc = ecdsa_p384_verify(pub, (size_t)publen, hash, sig, (size_t)slen);
        int got_valid = (rc == 0);
        if (got_valid != (c->valid != 0)) {
            if (fails < 20)
                printf("  FAIL  tcId %d: expected %s, got %s\n",
                       c->tcid, c->valid ? "valid" : "invalid",
                       got_valid ? "valid" : "invalid");
            fails++;
        } else if (c->valid) valid_ok++;
        else invalid_ok++;
    }
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;

    printf("  accepted-valid: %d   rejected-invalid: %d   failures: %d\n",
           valid_ok, invalid_ok, fails);
    printf("  (%.2f s for %d verifies, ~%.0f ms each)\n",
           secs, WP_NCASES, secs * 1000.0 / WP_NCASES);
    printf(fails ? "\nECDSA384 TEST: %d FAILURE(S)\n" : "\nECDSA384 TEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
