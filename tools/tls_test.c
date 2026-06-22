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
#include "transcript.h"
#include "key_schedule.h"
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

    printf("TLS 1.3 transcript (RFC 8446 §4.4.1):\n");
    {
        tls_transcript t;
        uint8_t h[32];

        tls_transcript_init(&t);
        tls_transcript_hash(&t, h);
        check("empty == SHA-256(\"\")", h, 32,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        /* streaming: "ab" then "c" must equal SHA-256("abc") */
        tls_transcript_init(&t);
        tls_transcript_update(&t, "ab", 2);
        tls_transcript_hash(&t, h);          /* snapshot must not end the stream */
        tls_transcript_update(&t, "c", 1);
        tls_transcript_hash(&t, h);
        check("streamed \"ab\"+\"c\" == SHA-256(\"abc\")", h, 32,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    printf("TLS 1.3 key schedule (RFC 8448 §3 trace):\n");
    {
        /* The RFC 8448 "Simple 1-RTT Handshake" trace. The key schedule depends
         * only on SHA-256 + the ECDHE secret (not the AEAD), so its secrets are
         * an authoritative reference even though that trace uses AES-128-GCM. */
        uint8_t cpriv[32], spub[32], ecdhe[32], hello_hash[32];
        unhex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005", cpriv);
        unhex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f", spub);

        /* X25519 ties into the schedule: derive the shared secret ourselves */
        x25519(ecdhe, cpriv, spub);
        check("ECDHE shared secret", ecdhe, 32,
              "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

        /* Transcript-Hash(ClientHello..ServerHello) — RFC 8448 published value */
        unhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8", hello_hash);

        tls_key_schedule ks;
        tls_key_schedule_derive(&ks, ecdhe, hello_hash);
        check("early secret", ks.early_secret, 32,
              "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        check("handshake secret", ks.handshake_secret, 32,
              "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        check("master secret", ks.master_secret, 32,
              "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        check("client hs traffic secret", ks.client_hs_traffic, 32,
              "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        check("server hs traffic secret", ks.server_hs_traffic, 32,
              "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

        /* HKDF-Expand-Label "key"/"iv" — RFC 8448 server handshake keys
         * (16-byte AES-128 key, 12-byte iv: exercises the label encoding) */
        uint8_t key[16], iv[12];
        tls_traffic_keys(ks.server_hs_traffic, key, 16, iv, 12);
        check("server write key (expand-label)", key, 16, "3fce516009c21727d0f2e4e86ee403bc");
        check("server write iv  (expand-label)", iv, 12, "5d313eb2671276ee13000b30");
    }

    printf(failures ? "\nTLS TEST: %d FAILURE(S)\n" : "\nTLS TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
