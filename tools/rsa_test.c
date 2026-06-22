/* Host-side crypto-math tests for the PKI path: big-integer arithmetic and RSA.
 * No ASN.1, no certificates — pure math, checked against independent references
 * (Python). Build/run: `make rsa-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "bignum.h"
#include "rsa.h"

static int failures;

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
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

static void bn_hex(bignum *a, const char *hex)
{
    uint8_t b[1024];
    int n = unhex(hex, b);
    bignum_from_bytes(a, b, (size_t)n);
}

/* equal to the value encoded by `hex` (big-endian)? */
static int bn_eq_hex(const bignum *a, const char *hex)
{
    bignum want; bn_hex(&want, hex);
    return bignum_cmp(a, &want) == 0;
}

int main(void)
{
    /* vectors from /tmp/bnvec.py (Python as the independent reference) */
    #define A    "f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafebabe0011223344556677"
    #define B    "0123456789abcdeffedcba9876543210112233445566778899aabbccddeeff00"
    #define MODM "fffffffffffffffffffffffffffffffeffffffffffffffff"

    printf("bignum — arithmetic vs Python:\n");
    {
        bignum a, b, r;
        bn_hex(&a, A); bn_hex(&b, B);

        check_ok("cmp(A,B) == 1", bignum_cmp(&a, &b) == 1);
        check_ok("cmp(B,A) == -1", bignum_cmp(&b, &a) == -1);
        check_ok("cmp(A,A) == 0", bignum_cmp(&a, &a) == 0);

        bignum_add(&r, &a, &b);
        check_ok("A + B", bn_eq_hex(&r, "f205182b3e516477774614e3b281501fefcff2342065324699bbde0022446577"));

        bignum_sub(&r, &a, &b);
        check_ok("A - B", bn_eq_hex(&r, "efbe8d5c2af9c897798c9fb2c5d8ebffcd8b8bab759843356666666666666777"));

        bignum_mul(&r, &a, &b);
        check_ok("A * B", bn_eq_hex(&r, "01121200deab6711990079029d4905d3d4e05e105f72bfad6b041a08281f6565458e3b0e404e761efcf74b5f9a621c444efddf29a0a4fb751ea4e5bf0eb28900"));

        bignum_shl1(&r, &a);
        check_ok("A << 1", bn_eq_hex(&r, "01e1c3a587694b2d0ef0d2b496785a3c1fbd5b7ddf95fd757c0022446688aaccee"));

        bignum m; bn_hex(&m, MODM);
        bignum_mod(&r, &a, &m);
        check_ok("A mod M", bn_eq_hex(&r, "78695a4b3c2d1e10cf8f91b37fa45145f0f2f4f6f8fafcfe"));

        /* carry across a limb boundary: 0xffffffff + 1 == 0x100000000 */
        bignum x, y;
        bn_hex(&x, "ffffffff"); bignum_set_u32(&y, 1);
        bignum_add(&r, &x, &y);
        check_ok("0xffffffff + 1 carries", bn_eq_hex(&r, "0100000000"));

        check_ok("bitlen(A) == 256", bignum_bitlen(&a) == 256);
        check_ok("is_zero(0)", (bignum_set_u32(&r, 0), bignum_is_zero(&r)));
        check_ok("!is_zero(A)", !bignum_is_zero(&a));

        uint8_t buf[32];
        check_ok("to_bytes round-trips", bignum_to_bytes(&a, buf, 32) == 0 && (bn_hex(&x, A), bignum_from_bytes(&y, buf, 32) == 0) && bignum_cmp(&x, &y) == 0);
        check_ok("to_bytes rejects undersized buffer", bignum_to_bytes(&a, buf, 8) == -1);
    }

    printf("bignum — modexp vs Python:\n");
    {
        bignum base, e, m, r;
        bn_hex(&base, "deadbeefcafe1234");
        bn_hex(&e, "010001");
        bn_hex(&m, "c0ffee00112233445566778899aabbccddeeff00fedcba9876543210");
        bignum_modexp(&r, &base, &e, &m);
        check_ok("base^65537 mod m", bn_eq_hex(&r, "482f5eba6d4b4167ac5da30cd2ef54e4161e4112389a4290fc2e9f10"));
    }

    printf("RSA — public op + PKCS#1 v1.5 verify vs Python:\n");
    {
        /* toy 640-bit RSA key + a real PKCS#1 v1.5 signature, from /tmp/rsavec.py */
        #define RSA_N   "9c00000000000000000000000000000000000000000000000000000000000000000000000000009bf00000000000000000000000000000000000000000000000000000000000000000000000000000bf"
        #define RSA_SIG "3b26ad36a19c6841ebad1618707085e83e952e4f4f33d0ce1c12fad3db98c566b5e97ef6df93a5f0b5422a858a0941931a12ee7ce5a288f4f45cd1a578a5a3beef972f9c67b96b09f4143c13f77c9309"
        #define RSA_DI  "3031300d0609608648016503040201050004201bbb677fdb973e9ae1ae6e796311364f7f6676ffc676077de6ac94399d7aef71"
        #define RSA_EM  "0001ffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d0609608648016503040201050004201bbb677fdb973e9ae1ae6e796311364f7f6676ffc676077de6ac94399d7aef71"
        uint8_t n[80], sig[80], di[64], em[80], e[3] = { 0x01, 0x00, 0x01 };  /* 65537 */
        int nlen  = unhex(RSA_N, n);
        int siglen= unhex(RSA_SIG, sig);
        int dilen = unhex(RSA_DI, di);

        int k = rsa_public(n, nlen, e, sizeof e, sig, siglen, em, sizeof em);
        char emhex[200]; for (int i = 0; i < k; i++) sprintf(emhex + i*2, "%02x", em[i]);
        check_ok("rsa_public: sig^e mod n == EM", k == 80 && strcmp(emhex, RSA_EM) == 0);

        check_ok("PKCS#1 v1.5 verify accepts a valid signature",
                 rsa_pkcs1_v15_verify(n, nlen, e, sizeof e, sig, siglen, di, dilen) == 0);

        uint8_t bad_di[64]; memcpy(bad_di, di, dilen); bad_di[dilen-1] ^= 1;
        check_ok("verify rejects a tampered digest",
                 rsa_pkcs1_v15_verify(n, nlen, e, sizeof e, sig, siglen, bad_di, dilen) == -1);

        uint8_t bad_sig[80]; memcpy(bad_sig, sig, siglen); bad_sig[siglen-1] ^= 1;
        check_ok("verify rejects a tampered signature",
                 rsa_pkcs1_v15_verify(n, nlen, e, sizeof e, bad_sig, siglen, di, dilen) == -1);

        check_ok("rsa_public rejects input >= modulus",
                 rsa_public(n, nlen, e, sizeof e, n, nlen, em, sizeof em) == -1);
    }

    printf(failures ? "\nRSA TEST: %d FAILURE(S)\n" : "\nRSA TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
