/* Host-side TLS test: verifies the tls/ protocol layer on top of the verified
 * crypto/ primitives. No QEMU, no networking. Build/run: `make tls-test`.
 *
 * TLS 1.3 has no published ChaCha20-Poly1305 record KAT in the spec body, so the
 * record layer is pinned three ways: (1) seqnum->nonce derivation against
 * hand-computed values, (2) a byte-for-byte cross-check of the framing against
 * the RFC-verified AEAD invoked manually, and (3) round-trip + tamper/seq
 * rejection behaviour. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "record.h"
#include "chacha20poly1305.h"

static int failures;

static void tohex(const uint8_t *b, int n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[b[i] >> 4]; out[i*2+1] = h[b[i] & 15]; }
    out[n*2] = 0;
}

static void check(const char *name, const uint8_t *got, int n, const char *want)
{
    char hex[1100];
    tohex(got, n, hex);
    if (strcmp(hex, want) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want);
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

int main(void)
{
    const char *msg = "hello tls 1.3 record layer";
    size_t mlen = strlen(msg);
    char msghex[256];
    tohex((const uint8_t *)msg, (int)mlen, msghex);

    uint8_t key[32], iv[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) iv[i]  = (uint8_t)(0x40 + i);

    printf("TLS 1.3 record nonce (RFC 8446 §5.3):\n");
    {
        uint8_t z[12] = {0}, n[12];
        tls_record_nonce(n, z, 0);
        check("iv=0 seq=0",  n, 12, "000000000000000000000000");
        tls_record_nonce(n, z, 1);
        check("iv=0 seq=1",  n, 12, "000000000000000000000001");
        tls_record_nonce(n, z, 0x0102030405060708ULL);
        check("iv=0 seq=0x0102030405060708", n, 12, "000000000102030405060708");
        uint8_t f[12]; memset(f, 0xff, 12);
        tls_record_nonce(n, f, 1);
        check("iv=ff.. seq=1", n, 12, "fffffffffffffffffffffffe");
    }

    printf("TLS 1.3 record seal/open:\n");
    {   /* round-trip recovers content + inner type, seq advances on both ends */
        tls_record_keys w, r;
        tls_record_init(&w, key, iv);
        tls_record_init(&r, key, iv);
        uint8_t rec[256], out[256], type;

        int rl = tls_record_seal(&w, TLS_CONTENT_HANDSHAKE,
                                 (const uint8_t *)msg, mlen, rec, sizeof rec);
        check_int("seal wire length", rl, (int)(5 + mlen + 1 + 16));
        check_int("wire opaque_type == application_data", rec[0], 23);
        check_int("wire legacy_version 0x03,0x03", (rec[1]<<8)|rec[2], 0x0303);

        int cl = tls_record_open(&r, rec, rl, out, sizeof out, &type);
        check_int("open content length", cl, (int)mlen);
        check_int("open inner type == handshake", type, TLS_CONTENT_HANDSHAKE);
        check("open recovered content", out, cl, msghex);
        check_int("write seq advanced", (int)w.seq, 1);
        check_int("read seq advanced",  (int)r.seq, 1);
    }

    {   /* cross-check: the record equals the verified AEAD framed by hand */
        tls_record_keys w; tls_record_init(&w, key, iv);
        uint8_t rec[256];
        int rl = tls_record_seal(&w, TLS_CONTENT_APPLICATION_DATA,
                                 (const uint8_t *)msg, mlen, rec, sizeof rec);

        size_t inner_len = mlen + 1, enc_len = inner_len + 16;
        uint8_t inner[256], ct[256], tag[16], nonce[12], aad[5], expect[256];
        memcpy(inner, msg, mlen); inner[mlen] = TLS_CONTENT_APPLICATION_DATA;
        tls_record_nonce(nonce, iv, 0);
        aad[0] = 23; aad[1] = 3; aad[2] = 3;
        aad[3] = (uint8_t)(enc_len >> 8); aad[4] = (uint8_t)(enc_len & 0xff);
        chacha20poly1305_seal(ct, tag, key, nonce, aad, 5, inner, inner_len);
        memcpy(expect, aad, 5);
        memcpy(expect + 5, ct, inner_len);
        memcpy(expect + 5 + inner_len, tag, 16);

        char eh[1100]; tohex(expect, (int)(5 + enc_len), eh);
        check("record == manual AEAD framing", rec, rl, eh);
    }

    {   /* sequence separation: identical plaintext, consecutive records differ */
        tls_record_keys w; tls_record_init(&w, key, iv);
        uint8_t r0[256], r1[256];
        int l0 = tls_record_seal(&w, TLS_CONTENT_APPLICATION_DATA, (const uint8_t *)msg, mlen, r0, sizeof r0);
        int l1 = tls_record_seal(&w, TLS_CONTENT_APPLICATION_DATA, (const uint8_t *)msg, mlen, r1, sizeof r1);
        check_int("consecutive records same length", l0, l1);
        check_int("seq 0 vs seq 1 differ on the wire", memcmp(r0, r1, l0) != 0, 1);
    }

    printf("TLS 1.3 record rejection:\n");
    {
        tls_record_keys w; tls_record_init(&w, key, iv);
        uint8_t rec[256], out[256], type;
        int rl = tls_record_seal(&w, TLS_CONTENT_APPLICATION_DATA, (const uint8_t *)msg, mlen, rec, sizeof rec);

        uint8_t bad[256]; memcpy(bad, rec, rl); bad[7] ^= 1;   /* flip a ciphertext byte */
        tls_record_keys r1; tls_record_init(&r1, key, iv);
        check_int("tampered record -> -1", tls_record_open(&r1, bad, rl, out, sizeof out, &type), -1);

        tls_record_keys r2; tls_record_init(&r2, key, iv); r2.seq = 1;  /* wrong seq */
        check_int("wrong sequence -> -1", tls_record_open(&r2, rec, rl, out, sizeof out, &type), -1);

        tls_record_keys r3; tls_record_init(&r3, key, iv);
        check_int("correct sequence -> ok", tls_record_open(&r3, rec, rl, out, sizeof out, &type), (int)mlen);
    }

    printf(failures ? "\nTLS TEST: %d FAILURE(S)\n" : "\nTLS TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
