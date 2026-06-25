/* Host-side P-384 field/scalar test (Phase 14.x.2). Checks GF(p) and GF(n)
 * arithmetic against vectors computed independently in Python from the canonical
 * secp384r1 p and n, plus self-consistency identities (a*inv(a)=1, round-trips)
 * and reduction edge cases ((p-1)^2 = 1, p-1+1 = 0). Mirrors the P-256 test.
 * Build/run: `make p384-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "p384_field.h"
#include "p384_scalar.h"

static int failures;

static void tohex(const uint8_t *b, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}
static int unhex(const char *s, uint8_t *out)
{
    int n = 0;
    for (; s[0] && s[1]; s += 2) {
        int hi = s[0] <= '9' ? s[0]-'0' : (s[0]|32)-'a'+10;
        int lo = s[1] <= '9' ? s[1]-'0' : (s[1]|32)-'a'+10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}
static void check_hex(const char *name, const uint8_t *got48, const char *want)
{
    char hex[97]; tohex(got48, 48, hex);
    if (strcmp(hex, want) == 0) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want); failures++; }
}
static void check_int(const char *name, int got, int want)
{
    if (got == want) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n        got  %d  want %d\n", name, got, want); failures++; }
}

#define A    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
#define B    "00ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211"
#define ONE  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
#define ZERO "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
#define ALLF "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

int main(void)
{
    uint8_t ab[48], bb[48], o[48], t[48];
    unhex(A, ab); unhex(B, bb);

    printf("P-384 field GF(p) (vectors vs Python):\n");
    fe384 a, b, r, s;
    check_int("from_bytes(A) accepted", fe384_from_bytes(&a, ab), 0);
    check_int("from_bytes(B) accepted", fe384_from_bytes(&b, bb), 0);

    fe384_add(&r, &a, &b); fe384_to_bytes(o, &r);
    check_hex("(a+b) mod p", o, "122222222222222222222222222221111222222222222222222222222222211112222222222222222222222222222111");
    fe384_sub(&r, &a, &b); fe384_to_bytes(o, &r);
    check_hex("(a-b) mod p", o, "1022446688aaccef1133557799bbdcef1022446688aaccef1133557799bbdcef1022446688aaccef1133557799bbdcef");
    fe384_mul(&r, &a, &b); fe384_to_bytes(o, &r);
    check_hex("(a*b) mod p", o, "aafbc2dd1a9c5013c54269183b6d7c40098eab1864d2077ca9152633c09c300d69eba0839092da89c2b87b0f79ef1ee2");
    fe384_sqr(&r, &a); fe384_to_bytes(o, &r);
    check_hex("(a*a) mod p", o, "e7dda1308ddb3aceb91c19f8fb477f1c21d59b728150685195deb70eae010d4af9133be7f231e7f22f9dfdda58a4dd9d");
    fe384_inv(&r, &a); fe384_to_bytes(o, &r);
    check_hex("a^(p-2) mod p", o, "774e4794ef19c725c0b14f174119e3f7232c41d26ccb1e8761201adb8271f21c6a5b963055075441ec4a3399d1d320b1");

    /* self-consistency + reduction edge cases */
    fe384_mul(&s, &b, &a); fe384_to_bytes(t, &s); fe384_mul(&r, &a, &b); fe384_to_bytes(o, &r);
    check_int("a*b == b*a", memcmp(o, t, 48) == 0, 1);
    fe384_inv(&s, &a); fe384_mul(&r, &a, &s); fe384_to_bytes(o, &r);
    check_hex("a * a^-1 == 1", o, ONE);
    fe384_add(&r, &a, &b); fe384_sub(&s, &r, &b); fe384_to_bytes(o, &s);
    check_hex("(a+b)-b == a", o, A);
    {   uint8_t pm1[48]; unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe", pm1);
        fe384 pe, one; check_int("from_bytes(p-1) accepted", fe384_from_bytes(&pe, pm1), 0);
        fe384_sqr(&r, &pe); fe384_to_bytes(o, &r);
        check_hex("(p-1)^2 == 1", o, ONE);
        fe384_set_u32(&one, 1); fe384_add(&r, &pe, &one); fe384_to_bytes(o, &r);
        check_hex("(p-1)+1 == 0", o, ZERO);
    }
    {   uint8_t pv[48]; unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", pv);
        fe384 x; check_int("from_bytes(p) rejected",     fe384_from_bytes(&x, pv), -1);
        uint8_t af[48]; unhex(ALLF, af);
        check_int("from_bytes(2^384-1) rejected", fe384_from_bytes(&x, af), -1);
    }

    printf("P-384 scalar GF(n) (vectors vs Python):\n");
    sc384 sa, sb, sr, ss;
    check_int("from_bytes(A) accepted", sc384_from_bytes(&sa, ab), 0);
    check_int("from_bytes(B) accepted", sc384_from_bytes(&sb, bb), 0);
    sc384_mul(&sr, &sa, &sb); sc384_to_bytes(o, &sr);
    check_hex("(a*b) mod n", o, "005e59bde2aedebf23fbea8065f92346addb752194c75c6768648559775e84decc95e2954318a340638a9938c8500c32");
    sc384_inv(&sr, &sa); sc384_to_bytes(o, &sr);
    check_hex("a^(n-2) mod n", o, "91a7755713d55e7b9f0c08638979f27f360ca1b0f06c8761af1173a2fc86a23d25f141c2f4b3e2cb764418608724a180");
    {   uint8_t af[48]; unhex(ALLF, af); sc384 red;
        sc384_reduce(&red, af); sc384_to_bytes(o, &red);
        check_hex("(2^384-1) mod n", o, "000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68c");
    }
    sc384_inv(&ss, &sa); sc384_mul(&sr, &sa, &ss); sc384_to_bytes(o, &sr);
    check_hex("a * a^-1 == 1 (mod n)", o, ONE);
    sc384_add(&sr, &sa, &sb); sc384_sub(&ss, &sr, &sb); sc384_to_bytes(o, &ss);
    check_hex("(a+b)-b == a (mod n)", o, A);
    {   uint8_t nm1[48]; unhex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972", nm1);
        sc384 x; check_int("from_bytes(n-1) accepted", sc384_from_bytes(&x, nm1), 0);
        uint8_t nv[48]; unhex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", nv);
        check_int("from_bytes(n) rejected", sc384_from_bytes(&x, nv), -1);
    }

    printf(failures ? "\nP384 TEST: %d FAILURE(S)\n" : "\nP384 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
