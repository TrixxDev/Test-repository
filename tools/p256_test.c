/* Host-side test for P-256 field arithmetic (crypto/p256_field.c) against
 * vectors computed independently in Python (mod the secp256r1 prime). Covers
 * add/sub/mul/sqr/inv plus edge values (0, 1, p-1, near-2^256) and the
 * fe_from_bytes range check. Build/run: `make p256-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "p256_field.h"
#include "p256_scalar.h"

static int failures;

static void unhex(const char *h, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        int hi = h[i*2], lo = h[i*2+1];
        hi = (hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
        lo = (lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

static void check_fe(const char *name, const fe *got, const char *want_hex)
{
    uint8_t gb[32], wb[32];
    fe_to_bytes(gb, got);
    unhex(want_hex, wb);
    if (memcmp(gb, wb, 32) == 0) { printf("  PASS  %s\n", name); return; }
    char gh[65]; for (int i = 0; i < 32; i++) sprintf(gh + i*2, "%02x", gb[i]);
    printf("  FAIL  %s\n        got  %s\n        want %s\n", name, gh, want_hex);
    failures++;
}

static void check_int(const char *name, int got, int want)
{
    if (got == want) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s (got %d want %d)\n", name, got, want); failures++; }
}

static void check_sc(const char *name, const sc *got, const char *want_hex)
{
    uint8_t gb[32], wb[32];
    sc_to_bytes(gb, got);
    unhex(want_hex, wb);
    if (memcmp(gb, wb, 32) == 0) { printf("  PASS  %s\n", name); return; }
    char gh[65]; for (int i = 0; i < 32; i++) sprintf(gh + i*2, "%02x", gb[i]);
    printf("  FAIL  %s\n        got  %s\n        want %s\n", name, gh, want_hex);
    failures++;
}

struct fcase { const char *a, *b, *add, *sub, *mul, *sqr, *inv; };

#include "p256_field_vec.inc"    /* generated cases[],  P_HEX, PM1_HEX */
#include "p256_scalar_vec.inc"   /* generated scases[], RED_IN/OUT, N_HEX, NM1_HEX */

int main(void)
{
    printf("P-256 field arithmetic (mod p):\n");
    int ncases = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < ncases; i++) {
        const struct fcase *c = &cases[i];
        uint8_t ab[32], bb[32];
        fe a, b, r;
        unhex(c->a, ab); unhex(c->b, bb);
        check_int("  a is a valid field element (< p)", fe_from_bytes(&a, ab), 0);
        check_int("  b is a valid field element (< p)", fe_from_bytes(&b, bb), 0);

        char nm[64];
        sprintf(nm, "case %d: a + b", i); fe_add(&r, &a, &b); check_fe(nm, &r, c->add);
        sprintf(nm, "case %d: a - b", i); fe_sub(&r, &a, &b); check_fe(nm, &r, c->sub);
        sprintf(nm, "case %d: a * b", i); fe_mul(&r, &a, &b); check_fe(nm, &r, c->mul);
        sprintf(nm, "case %d: a^2",   i); fe_sqr(&r, &a);     check_fe(nm, &r, c->sqr);
        sprintf(nm, "case %d: a^-1",  i); fe_inv(&r, &a);     check_fe(nm, &r, c->inv);

        /* a * a^-1 == 1 for a != 0 */
        if (!fe_is_zero(&a)) {
            fe inv, prod, one; fe_set_u32(&one, 1);
            fe_inv(&inv, &a); fe_mul(&prod, &a, &inv);
            sprintf(nm, "case %d: a * a^-1 == 1", i);
            check_int(nm, fe_equal(&prod, &one), 1);
        }
    }

    /* fe_from_bytes range check: p must be rejected, p-1 accepted */
    {
        uint8_t pb[32], pm1[32]; fe t;
        unhex(P_HEX, pb); unhex(PM1_HEX, pm1);
        check_int("fe_from_bytes rejects p", fe_from_bytes(&t, pb), -1);
        check_int("fe_from_bytes accepts p-1", fe_from_bytes(&t, pm1), 0);
    }

    printf("P-256 scalar arithmetic (mod n):\n");
    int nsc = (int)(sizeof(scases) / sizeof(scases[0]));
    for (int i = 0; i < nsc; i++) {
        const struct fcase *c = &scases[i];
        uint8_t ab[32], bb[32]; sc a, b, r;
        unhex(c->a, ab); unhex(c->b, bb);
        sc_from_bytes(&a, ab); sc_from_bytes(&b, bb);
        char nm[64];
        sprintf(nm, "sc %d: a + b", i); sc_add(&r, &a, &b); check_sc(nm, &r, c->add);
        sprintf(nm, "sc %d: a - b", i); sc_sub(&r, &a, &b); check_sc(nm, &r, c->sub);
        sprintf(nm, "sc %d: a * b", i); sc_mul(&r, &a, &b); check_sc(nm, &r, c->mul);
        sprintf(nm, "sc %d: a^2",   i); sc_mul(&r, &a, &a); check_sc(nm, &r, c->sqr);
        sprintf(nm, "sc %d: a^-1",  i); sc_inv(&r, &a);     check_sc(nm, &r, c->inv);
        if (!sc_is_zero(&a)) {
            sc inv, prod, one; sc_set_zero(&one); one.v[0] = 1;
            sc_inv(&inv, &a); sc_mul(&prod, &a, &inv);
            sprintf(nm, "sc %d: a * a^-1 == 1", i);
            check_int(nm, sc_equal(&prod, &one), 1);
        }
    }
    {
        uint8_t in[32], nb[32], nm1[32]; sc r, t;
        unhex(RED_IN, in); sc_reduce(&r, in);
        check_sc("sc_reduce(n + 0x1234) == 0x1234", &r, RED_OUT);
        unhex(N_HEX, nb); unhex(NM1_HEX, nm1);
        check_int("sc_from_bytes rejects n", sc_from_bytes(&t, nb), -1);
        check_int("sc_from_bytes accepts n-1", sc_from_bytes(&t, nm1), 0);
    }

    printf(failures ? "\nP256 TEST: %d FAILURE(S)\n" : "\nP256 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
