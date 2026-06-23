/* Host-side test for P-256 field arithmetic (crypto/p256_field.c) against
 * vectors computed independently in Python (mod the secp256r1 prime). Covers
 * add/sub/mul/sqr/inv plus edge values (0, 1, p-1, near-2^256) and the
 * fe_from_bytes range check. Build/run: `make p256-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "p256_field.h"
#include "p256_scalar.h"
#include "p256_point.h"

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
#include "p256_point_vec.inc"    /* generated G/G2/G3/NEGG, kcases[], CURVE_B_HEX */

static void load_fe(fe *r, const char *hex)
{ uint8_t b[32]; unhex(hex, b); fe_from_bytes(r, b); }

static void load_point(p256_point *P, const char *xh, const char *yh)
{ fe x, y; load_fe(&x, xh); load_fe(&y, yh); p256_from_affine(P, &x, &y); }

/* check a computed point against an expected (infinity, or affine x/y hex) */
static void check_pt(const char *name, const p256_point *P,
                     int inf, const char *xh, const char *yh)
{
    if (inf) { check_int(name, p256_is_infinity(P), 1); return; }
    fe x, y; uint8_t xb[32], yb[32], exb[32], eyb[32];
    if (p256_to_affine(&x, &y, P) != 0) { check_int(name, 0, 1); return; }
    fe_to_bytes(xb, &x); fe_to_bytes(yb, &y);
    unhex(xh, exb); unhex(yh, eyb);
    check_int(name, (memcmp(xb, exb, 32) == 0 && memcmp(yb, eyb, 32) == 0), 1);
}

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

    /* ---- curve geometry: double/add on known points, then group invariants ---- */
    printf("P-256 point geometry (double / add):\n");
    {
        p256_point G, G2, G3, negG, O, r;
        p256_base_point(&G);
        load_point(&G2, G2_X, G2_Y);
        load_point(&G3, G3_X, G3_Y);
        load_point(&negG, NEGG_X, NEGG_Y);
        p256_set_infinity(&O);

        p256_double(&r, &G);            check_pt("2G = double(G)", &r, G2_INF, G2_X, G2_Y);
        p256_add(&r, &G, &G);           check_pt("2G = G + G",    &r, G2_INF, G2_X, G2_Y);
        p256_add(&r, &G2, &G);          check_pt("3G = 2G + G",   &r, G3_INF, G3_X, G3_Y);
        p256_add(&r, &G, &G2);          check_pt("3G = G + 2G",   &r, G3_INF, G3_X, G3_Y);

        p256_add(&r, &G, &O);           check_pt("G + O = G", &r, G_INF, G_X, G_Y);
        p256_add(&r, &O, &G);           check_pt("O + G = G", &r, G_INF, G_X, G_Y);
        p256_double(&r, &O);            check_int("double(O) = O", p256_is_infinity(&r), 1);
        p256_add(&r, &G, &negG);        check_int("G + (-G) = O", p256_is_infinity(&r), 1);
    }

    /* ---- scalar multiply against k*G ground truth, then n*G = O ---- */
    printf("P-256 scalar multiply (k*G):\n");
    {
        p256_point G, r;
        p256_base_point(&G);
        int nk = (int)(sizeof(kcases) / sizeof(kcases[0]));
        for (int i = 0; i < nk; i++) {
            const struct kcase *c = &kcases[i];
            uint8_t kb[32]; sc k;
            unhex(c->k, kb); sc_from_bytes(&k, kb);
            p256_scalar_mul(&r, &k, &G);
            char nm[48]; sprintf(nm, "k*G case %d", i);
            check_pt(nm, &r, c->inf, c->x, c->y);
        }
        /* n*G = O : the order check, the strongest single point-formula test */
        uint8_t nb[32]; sc nsc;
        unhex(N_HEX, nb); sc_from_bytes(&nsc, nb);   /* loads n (range check ignored) */
        p256_scalar_mul(&r, &nsc, &G);
        check_int("n*G = O (order check)", p256_is_infinity(&r), 1);
    }

    printf(failures ? "\nP256 TEST: %d FAILURE(S)\n" : "\nP256 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
