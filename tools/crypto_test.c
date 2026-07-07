/* Host-side crypto test: verifies the portable crypto/ primitives against known
 * answer vectors (NIST FIPS 180-4 for SHA-256, RFC 4231 for HMAC-SHA256). Runs
 * natively on the build host -- no QEMU, no OS -- so each primitive is checked in
 * isolation. Build/run: `make crypto-test`. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"
#include "sha384.h"
#include "hmac_sha256.h"
#include "hkdf.h"
#include "chacha20.h"
#include "poly1305.h"
#include "chacha20poly1305.h"
#include "x25519.h"

static int failures;

static void tohex(const uint8_t *b, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}

static void check(const char *name, const uint8_t *got, int n, const char *want)
{
    char hex[513];      /* up to 256 bytes -> 512 hex chars + NUL */
    tohex(got, n, hex);
    if (strcmp(hex, want) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want);
        failures++;
    }
}

static void check_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got == want) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %08x\n        want %08x\n", name, got, want);
        failures++;
    }
}

static void check_int(const char *name, int got, int want)
{
    if (got == want) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %d\n        want %d\n", name, got, want);
        failures++;
    }
}

/* Parse a hex string into bytes; returns the byte count. */
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

int main(void)
{
    uint8_t d[32];

    printf("SHA-256 (NIST FIPS 180-4):\n");
    sha256("", 0, d);
    check("\"\"", d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256("abc", 3, d);
    check("\"abc\"", d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *s2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(s2, strlen(s2), d);
    check("56-byte string", d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    {   /* one million 'a' */
        sha256_ctx c; sha256_init(&c);
        char buf[1000]; memset(buf, 'a', sizeof(buf));
        for (int i = 0; i < 1000; i++) sha256_update(&c, buf, sizeof(buf));
        sha256_final(&c, d);
        check("1,000,000 x 'a'", d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    {   /* SHA-384 / SHA-512 (NIST FIPS 180-4). The 112-byte two-block message and
         * the one-million-'a' case exercise multi-block + length-encoding paths. */
        uint8_t d64[64];
        const char *m2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"; /* 112 bytes */

        printf("SHA-384 (NIST FIPS 180-4):\n");
        sha384("", 0, d64);
        check("\"\"", d64, 48, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf"
                               "63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        sha384("abc", 3, d64);
        check("\"abc\"", d64, 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a"
                                  "43ff5bed8086072ba1e7cc2358baeca134c825a7");
        sha384(m2, 112, d64);
        check("112-byte string", d64, 48, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                                          "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
        {   sha512_ctx c; sha384_init(&c);
            char buf[1000]; memset(buf, 'a', sizeof(buf));
            for (int i = 0; i < 1000; i++) sha512_update(&c, buf, sizeof(buf));
            sha384_final(&c, d64);
            check("1,000,000 x 'a'", d64, 48, "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
                                              "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
        }

        printf("SHA-512 (NIST FIPS 180-4):\n");
        sha512("", 0, d64);
        check("\"\"", d64, 64, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        sha512("abc", 3, d64);
        check("\"abc\"", d64, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        sha512(m2, 112, d64);
        check("112-byte string", d64, 64, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                                          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        {   sha512_ctx c; sha512_init(&c);
            char buf[1000]; memset(buf, 'a', sizeof(buf));
            for (int i = 0; i < 1000; i++) sha512_update(&c, buf, sizeof(buf));
            sha512_final(&c, d64);
            check("1,000,000 x 'a'", d64, 64, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                                              "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        }
    }

    printf("HMAC-SHA256 (RFC 4231):\n");
    {   /* Test Case 1 */
        uint8_t key[20]; memset(key, 0x0b, sizeof(key));
        hmac_sha256(key, 20, "Hi There", 8, d);
        check("case 1", d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    {   /* Test Case 2 */
        hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
        check("case 2", d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
    {   /* Test Case 3: 20x 0xaa key, 50x 0xdd data */
        uint8_t key[20], data[50]; memset(key, 0xaa, 20); memset(data, 0xdd, 50);
        hmac_sha256(key, 20, data, 50, d);
        check("case 3", d, 32, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }
    {   /* Test Case 4: key 0x01..0x19 (25 bytes), 50x 0xcd data */
        uint8_t key[25], data[50];
        for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
        memset(data, 0xcd, 50);
        hmac_sha256(key, 25, data, 50, d);
        check("case 4", d, 32, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    }
    {   /* Test Case 6: 131-byte key (>block), "Test Using Larger Than Block-Size Key - Hash Key First" */
        uint8_t key[131]; memset(key, 0xaa, sizeof(key));
        const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
        hmac_sha256(key, 131, m, strlen(m), d);
        check("case 6 (long key)", d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    printf("HKDF-SHA256 (RFC 5869):\n");
    {   /* Test Case 1: basic, with salt and info */
        uint8_t ikm[80], salt[80], info[80], prk[32], okm[82];
        int ikmn  = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
        int saltn = unhex("000102030405060708090a0b0c", salt);
        int infon = unhex("f0f1f2f3f4f5f6f7f8f9", info);
        hkdf_extract(salt, saltn, ikm, ikmn, prk);
        check("case 1 PRK", prk, 32,
              "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        hkdf_expand(prk, info, infon, okm, 42);
        check("case 1 OKM (42)", okm, 42,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865");
    }
    {   /* Test Case 2: longer inputs and output */
        uint8_t ikm[80], salt[80], info[80], prk[32], okm[82];
        int ikmn = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f", ikm);
        int saltn = unhex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", salt);
        int infon = unhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", info);
        hkdf_extract(salt, saltn, ikm, ikmn, prk);
        check("case 2 PRK", prk, 32,
              "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        hkdf_expand(prk, info, infon, okm, 82);
        check("case 2 OKM (82)", okm, 82,
              "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
              "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
              "cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }
    {   /* Test Case 3: zero-length salt and info */
        uint8_t ikm[22], prk[32], okm[42];
        int ikmn = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
        hkdf_extract(NULL, 0, ikm, ikmn, prk);
        check("case 3 PRK (no salt)", prk, 32,
              "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        hkdf_expand(prk, NULL, 0, okm, 42);
        check("case 3 OKM (no info)", okm, 42,
              "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
              "9d201395faa4b61a96c8");
    }

    printf("ChaCha20 (RFC 8439):\n");
    {   /* §2.1.1 — the quarter-round on four words */
        uint32_t a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, e = 0x01234567;
        chacha20_quarterround(&a, &b, &c, &e);
        check_u32("quarter-round a", a, 0xea2a92f4);
        check_u32("quarter-round b", b, 0xcb1cf8ce);
        check_u32("quarter-round c", c, 0x4581472e);
        check_u32("quarter-round d", e, 0x5881c4bb);
    }
    {   /* §2.2.1 — the quarter-round applied to indices (2,7,8,13) of a state */
        uint32_t s[16] = {
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320 };
        chacha20_quarterround(&s[2], &s[7], &s[8], &s[13]);
        check_u32("state QR x[2]",  s[2],  0xbdb886dc);
        check_u32("state QR x[7]",  s[7],  0xcfacafd2);
        check_u32("state QR x[8]",  s[8],  0xe46bea80);
        check_u32("state QR x[13]", s[13], 0xccc07c79);
    }
    {   /* §2.3.2 — the block function: key 00..1f, nonce ..0900..4a.., counter 1 */
        uint8_t key[32], nonce[12] = {0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0}, ks[64];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        chacha20_ctx c; chacha20_init(&c, key, nonce, 1);
        chacha20_block(&c, ks);
        check("block keystream (counter 1)", ks, 64,
              "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
              "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }
    {   /* §2.4.2 — full encryption: same key, nonce ..00..4a.., counter 1 */
        uint8_t key[32], nonce[12] = {0,0,0,0, 0,0,0,0x4a, 0,0,0,0}, out[114];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        const char *pt = "Ladies and Gentlemen of the class of '99: If I "
                         "could offer you only one tip for the future, "
                         "sunscreen would be it.";
        chacha20_ctx c; chacha20_init(&c, key, nonce, 1);
        chacha20_xor(&c, (const uint8_t *)pt, out, strlen(pt));
        check("encrypt 114-byte plaintext", out, 114,
              "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
              "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
              "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
              "5af90bbf74a35be6b40b8eedf2785e42874d");
    }

    printf("Poly1305 (RFC 8439):\n");
    {   /* §2.5.2 — the canonical vector */
        uint8_t key[32], t[16];
        unhex("85d6be7857556d337f4452fe42d506a8"
              "0103808afb0db2fd4abff6af4149f51b", key);
        const char *m = "Cryptographic Forum Research Group";
        poly1305_auth(t, (const uint8_t *)m, 34, key);
        check("RFC 2.5.2 (34-byte)", t, 16, "a8061dc1305136c6c22b8baf0c0127a9");
    }
    {   /* Block-boundary lengths 0/1/15/16/17. Expected tags are from an
         * independent reference (OpenSSL 3 `openssl mac POLY1305`), key =
         * ASCII "this is 32-byte key for Poly1305", msg = bytes 0x01,0x02,... */
        uint8_t key[32], msg[17], t[16];
        for (int i = 0; i < 32; i++)
            key[i] = (uint8_t)"this is 32-byte key for Poly1305"[i];
        for (int i = 0; i < 17; i++) msg[i] = (uint8_t)(i + 1);

        poly1305_auth(t, msg, 0,  key);   /* empty -> tag == s == key[16..31] */
        check("len 0  (empty)",  t, 16, "6b657920666f7220506f6c7931333035");
        poly1305_auth(t, msg, 1,  key);
        check("len 1",           t, 16, "df414b8d89f84e9480d1cba8ab1f0a9b");
        poly1305_auth(t, msg, 15, key);
        check("len 15 (partial)", t, 16, "db5b4f3c41d3602dcbe6c1c03b41e244");
        poly1305_auth(t, msg, 16, key);
        check("len 16 (1 block)", t, 16, "d416d3589c8af931f434a38d19816811");
        poly1305_auth(t, msg, 17, key);
        check("len 17 (block+1)", t, 16, "540308e44971bfd8d85f717ad9bdfaac");
    }

    printf("ChaCha20-Poly1305 AEAD (RFC 8439 §2.8.2):\n");
    {
        uint8_t key[32], nonce[12], aad[12];
        unhex("808182838485868788898a8b8c8d8e8f"
              "909192939495969798999a9b9c9d9e9f", key);
        unhex("070000004041424344454647", nonce);
        int aadlen = unhex("50515253c0c1c2c3c4c5c6c7", aad);
        const char *pt = "Ladies and Gentlemen of the class of '99: If I "
                         "could offer you only one tip for the future, "
                         "sunscreen would be it.";
        size_t ptlen = strlen(pt);
        const char *want_ct =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116";
        const char *want_tag = "1ae10b594f09e26a7e902ecbd0600691";

        uint8_t ct[114], tag[16];
        chacha20poly1305_seal(ct, tag, key, nonce, aad, aadlen,
                              (const uint8_t *)pt, ptlen);
        check("seal ciphertext", ct, (int)ptlen, want_ct);
        check("seal tag",        tag, 16, want_tag);

        /* round-trip: open of an untampered record returns 0 and recovers pt */
        uint8_t out[114];
        char pthex[256];
        tohex((const uint8_t *)pt, (int)ptlen, pthex);
        check_int("open (valid) returns 0",
                  chacha20poly1305_open(out, key, nonce, aad, aadlen, ct, ptlen, tag), 0);
        check("open recovered plaintext", out, (int)ptlen, pthex);

        /* the property TLS depends on: any single-byte tamper must FAIL open */
        {   uint8_t bad[114]; for (size_t i=0;i<ptlen;i++) bad[i]=ct[i]; bad[0] ^= 1;
            check_int("flip ciphertext -> FAIL",
                      chacha20poly1305_open(out, key, nonce, aad, aadlen, bad, ptlen, tag), -1); }
        {   uint8_t badaad[12]; for (int i=0;i<aadlen;i++) badaad[i]=aad[i]; badaad[0] ^= 1;
            check_int("flip AAD -> FAIL",
                      chacha20poly1305_open(out, key, nonce, badaad, aadlen, ct, ptlen, tag), -1); }
        {   uint8_t badtag[16]; for (int i=0;i<16;i++) badtag[i]=tag[i]; badtag[15] ^= 0x80;
            check_int("flip tag -> FAIL",
                      chacha20poly1305_open(out, key, nonce, aad, aadlen, ct, ptlen, badtag), -1); }
    }

    printf("X25519 (RFC 7748):\n");
    {   /* §5.2 — scalar * u, vector 1 */
        uint8_t k[32], u[32], out[32];
        unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k);
        unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
        x25519(out, k, u);
        check("scalarmult vector 1", out, 32,
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }
    {   /* §5.2 — scalar * u, vector 2 */
        uint8_t k[32], u[32], out[32];
        unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k);
        unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
        x25519(out, k, u);
        check("scalarmult vector 2", out, 32,
              "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }
    {   /* §5.2 — iterative test, 1 iteration: X25519(9, 9) */
        uint8_t base[32] = {9}, out[32];
        x25519(out, base, base);
        check("iterative (1 iter)", out, 32,
              "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }
    {   /* §6.1 — Diffie-Hellman: both sides derive the same shared secret */
        uint8_t a[32], b[32], apub[32], bpub[32], ka[32], kb[32];
        unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
        unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
        x25519_base(apub, a);
        check("Alice public", apub, 32,
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        x25519_base(bpub, b);
        check("Bob public", bpub, 32,
              "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        x25519(ka, a, bpub);
        x25519(kb, b, apub);
        check("shared secret", ka, 32,
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        check_int("both sides agree", memcmp(ka, kb, 32) == 0, 1);
    }

    printf(failures ? "\nCRYPTO TEST: %d FAILURE(S)\n" : "\nCRYPTO TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
