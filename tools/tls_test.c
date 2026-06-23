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
#include "handshake.h"
#include "client.h"
#include "conn.h"
#include "cert.h"
#include "x509.h"
#include "verify_cert.h"
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

/* Does haystack contain needle? (for structural ClientHello checks) */
static int contains(const uint8_t *hay, size_t hn, const uint8_t *need, size_t nn)
{
    if (nn > hn) return 0;
    for (size_t i = 0; i + nn <= hn; i++) {
        size_t j = 0; while (j < nn && hay[i+j] == need[j]) j++;
        if (j == nn) return 1;
    }
    return 0;
}

/* Minimal ServerHello builder for exercising the parser (the client never builds
 * one; a loopback "server" does). Returns the message length. */
static int build_server_hello(uint8_t *o, const uint8_t random[32],
                              uint16_t cipher, const uint8_t pub[32])
{
    int n = 0;
    o[n++] = TLS_HS_SERVER_HELLO; o[n++] = 0; /* len hi24 patched below */
    int lenpos = n; n += 2;
    o[n++] = 0x03; o[n++] = 0x03;             /* legacy_version */
    for (int i=0;i<32;i++) o[n++] = random[i];
    o[n++] = 32; for (int i=0;i<32;i++) o[n++] = 0;   /* session_id_echo */
    o[n++] = (uint8_t)(cipher>>8); o[n++] = (uint8_t)cipher;
    o[n++] = 0;                               /* legacy_compression_method */
    int extpos = n; n += 2;                    /* extensions length */
    /* supported_versions (43): selected_version 0x0304 (no list in SH) */
    o[n++]=0;o[n++]=43; o[n++]=0;o[n++]=2; o[n++]=0x03;o[n++]=0x04;
    /* key_share (51): single KeyShareEntry { group, klen, key } */
    o[n++]=0;o[n++]=51; o[n++]=0;o[n++]=36;
    o[n++]=0x00;o[n++]=0x1d; o[n++]=0;o[n++]=32; for(int i=0;i<32;i++) o[n++]=pub[i];
    int extlen = n - extpos - 2;
    o[extpos] = (uint8_t)(extlen>>8); o[extpos+1] = (uint8_t)extlen;
    int body = n - 4;
    o[lenpos] = (uint8_t)(body>>8); o[lenpos+1] = (uint8_t)body;  /* 24-bit len, hi byte 0 */
    return n;
}

/* Build a generic handshake message: type | uint24(len) | body. */
static int build_hs(uint8_t *o, uint8_t type, const uint8_t *body, int blen)
{
    o[0] = type; o[1] = 0; o[2] = (uint8_t)(blen >> 8); o[3] = (uint8_t)blen;
    for (int i = 0; i < blen; i++) o[4 + i] = body[i];
    return 4 + blen;
}

/* Wrap a body in a plaintext TLS record (for the loopback "server"'s SH). */
static int plaintext_wrap(uint8_t *o, uint8_t ctype, const uint8_t *body, int blen)
{
    o[0] = ctype; o[1] = 0x03; o[2] = 0x03;
    o[3] = (uint8_t)(blen >> 8); o[4] = (uint8_t)blen;
    for (int i = 0; i < blen; i++) o[5 + i] = body[i];
    return 5 + blen;
}

/* Install a record epoch from a traffic secret (server-side mirror of the conn). */
static void epoch_from_secret(tls_record_keys *k, const uint8_t secret[32])
{
    uint8_t key[32], iv[12];
    tls_traffic_keys(secret, key, 32, iv, 12);
    tls_record_init(k, key, iv);
}

/* Wrap a DER certificate in a TLS 1.3 Certificate handshake message (one entry,
 * empty request context, empty entry extensions). Returns the message length. */
static int build_cert_msg(uint8_t *o, const uint8_t *der, int derlen)
{
    int n = 0;
    o[n++] = TLS_HS_CERTIFICATE; o[n++] = 0; o[n++] = 0; o[n++] = 0;   /* len patched below */
    o[n++] = 0;                                                        /* request context: empty */
    int listlen = 3 + derlen + 2;
    o[n++] = (uint8_t)(listlen >> 16); o[n++] = (uint8_t)(listlen >> 8); o[n++] = (uint8_t)listlen;
    o[n++] = (uint8_t)(derlen >> 16); o[n++] = (uint8_t)(derlen >> 8); o[n++] = (uint8_t)derlen;
    for (int i = 0; i < derlen; i++) o[n++] = der[i];
    o[n++] = 0; o[n++] = 0;                                            /* entry extensions: empty */
    int body = n - 4;
    o[1] = (uint8_t)(body >> 16); o[2] = (uint8_t)(body >> 8); o[3] = (uint8_t)body;
    return n;
}

/* an unrelated self-signed RSA certificate (RFC 8448 §3) — a "wrong" root */
#define RFC_DER_CERT "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1"

/* synthetic CA (self-signed) + leaf signed by it (from tools/mkchain) */
#define T_CA_CERT   "308201203081cba003020102020101300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3019311730150603550403130e4175726f72612054657374204341305c300d06092a864886f70d0101010500034b00304802410090000000000000000000000000000000000000000000000076a99b4b205252c58000000000000000000000000000000000000000000000cb554b6f660d0ed8f10203010001300d06092a864886f70d01010b05000341000be6fba8be2e9d3870633669470a678f07d21a0ce83577907562753c9642618b4e40c2b8dcb38dacdadd9fce3016b1c63ca3836a215123d35cc450f07e8e5adf"
#define T_LEAF_CERT "3082015b30820105a003020102020102300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d305c300d06092a864886f70d0101010500034b003048024100a90000000000000000000000000000000000000000000000808d12e6b859300e6000000000000000000000000000000000000000000000eb78902914235bf6fd0203010001a33b303930370603551d110430302e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d820e2a2e746573742e6578616d706c65300d06092a864886f70d01010b05000341005189bd07db7e3af5ce89ad7c486323c2102f28b1f0f11885f56e5f3ddf3aef93bd32e369eeafb4a833a3cc0ca84fd471766c8a5b3532a31173da96fcf3cbba34"

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

    printf("TLS 1.3 handshake messages (RFC 8446 §4):\n");
    {
        /* deterministic ephemeral keys for client and server */
        uint8_t cpriv[32], cpub[32], spriv[32], spub[32], crand[32], srand[32];
        for (int i=0;i<32;i++) { cpriv[i]=(uint8_t)(i+1); spriv[i]=(uint8_t)(0x80+i);
                                 crand[i]=(uint8_t)(0xa0+i); srand[i]=(uint8_t)(0x50+i); }
        x25519_base(cpub, cpriv);
        x25519_base(spub, spriv);

        /* ClientHello: structurally well-formed, carries our key_share + SNI */
        uint8_t ch[1024];
        int chlen = tls_build_client_hello(ch, sizeof ch, crand, cpub, "example.com");
        check_int("ClientHello builds", chlen > 0, 1);
        check_int("ClientHello type == client_hello", ch[0], TLS_HS_CLIENT_HELLO);
        check_int("ClientHello length field consistent",
                  (int)(((ch[1]<<16)|(ch[2]<<8)|ch[3]) == chlen - 4), 1);
        check_int("ClientHello carries our key_share", contains(ch, chlen, cpub, 32), 1);
        check_int("ClientHello carries SNI host",
                  contains(ch, chlen, (const uint8_t*)"example.com", 11), 1);

        /* ServerHello: parse extracts the cipher suite and server key_share */
        uint8_t sh[256];
        int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        uint16_t suite = 0; uint8_t got_spub[32];
        check_int("ServerHello parses", tls_parse_server_hello(sh, shlen, &suite, got_spub), 0);
        check_int("negotiated ChaCha20-Poly1305", suite == TLS_CIPHER_CHACHA20_POLY1305_SHA256, 1);
        check_int("server key_share extracted", memcmp(got_spub, spub, 32) == 0, 1);

        /* end-to-end loopback: both sides reach identical handshake secrets */
        uint8_t cs[32], ss[32], hello_hash[32];
        x25519(cs, cpriv, got_spub);    /* client: priv_c * pub_s */
        x25519(ss, spriv, cpub);        /* server: priv_s * pub_c */
        check_int("ECDHE agrees on both sides", memcmp(cs, ss, 32) == 0, 1);

        tls_transcript tr; tls_transcript_init(&tr);
        tls_transcript_update(&tr, ch, chlen);
        tls_transcript_update(&tr, sh, shlen);
        tls_transcript_hash(&tr, hello_hash);

        tls_key_schedule kc, ksv;
        tls_key_schedule_derive(&kc, cs, hello_hash);
        tls_key_schedule_derive(&ksv, ss, hello_hash);
        check_int("client/server agree: server hs traffic",
                  memcmp(kc.server_hs_traffic, ksv.server_hs_traffic, 32) == 0, 1);
        check_int("client/server agree: client hs traffic",
                  memcmp(kc.client_hs_traffic, ksv.client_hs_traffic, 32) == 0, 1);

        /* Finished round-trip over a transcript hash */
        uint8_t fk[32], vd[32], thash[32];
        tls_transcript_hash(&tr, thash);             /* stand-in transcript point */
        tls_finished_key(fk, ksv.server_hs_traffic);
        tls_finished_verify_data(vd, fk, thash);
        check_int("peer Finished verifies", tls_check_finished(fk, thash, vd), 0);
        uint8_t bad[32]; memcpy(bad, vd, 32); bad[0] ^= 1;
        check_int("tampered Finished rejected", tls_check_finished(fk, thash, bad), -1);
    }

    printf("TLS 1.3 client FSM (deterministic loopback handshake):\n");
    {
        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+3); spriv[i]=(uint8_t)(0x90+i);
                                crand[i]=(uint8_t)(0x11+i); srand[i]=(uint8_t)(0x22+i); }

        tls_client cl;
        tls_client_init(&cl, "example.com", cpriv, crand);
        check_int("init state START", cl.state, TLS_ST_START);
        check_int("init phase EARLY", cl.phase, TLS_PHASE_EARLY);

        uint8_t ch[1024];
        int chlen = tls_client_start(&cl, ch, sizeof ch);
        check_int("start emits ClientHello", (chlen > 0 && ch[0] == TLS_HS_CLIENT_HELLO), 1);
        check_int("after start: WAIT_SH", cl.state, TLS_ST_WAIT_SH);

        /* server side: mirror the transcript and derive the same keys */
        uint8_t spub[32], cpub[32];
        x25519_base(spub, spriv);
        x25519_base(cpub, cpriv);

        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256];
        int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);

        uint8_t hello_hash[32], ecdhe[32];
        tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss;
        tls_key_schedule_derive(&kss, ecdhe, hello_hash);

        /* dummy EE / Certificate / CertificateVerify (client only transcripts them) */
        uint8_t ee[64], cert[64], cv[64];
        int eelen   = build_hs(ee,   TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        int certlen = build_hs(cert, TLS_HS_CERTIFICATE,          (const uint8_t*)"\x00\x00\x00\x00", 4);
        int cvlen   = build_hs(cv,   TLS_HS_CERTIFICATE_VERIFY,   (const uint8_t*)"\x08\x04\x00\x00", 4);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, cert, certlen);
        tls_transcript_update(&ts, cv, cvlen);

        /* server Finished over Transcript(CH..CV) */
        uint8_t sfk[32], thash_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, thash_cv);
        tls_finished_verify_data(svd, sfk, thash_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);
        tls_transcript_update(&ts, sfin, sfinlen);

        /* drive the client FSM through the server flight */
        uint8_t out[64]; size_t outlen;
        check_int("recv SH -> 0", tls_client_recv_handshake(&cl, sh, shlen, out, sizeof out, &outlen), 0);
        check_int("after SH: WAIT_EE", cl.state, TLS_ST_WAIT_EE);
        check_int("after SH: phase HANDSHAKE", cl.phase, TLS_PHASE_HANDSHAKE);
        check_int("FSM/server agree: hs traffic secret",
                  memcmp(cl.ks.server_hs_traffic, kss.server_hs_traffic, 32) == 0, 1);

        tls_client_recv_handshake(&cl, ee, eelen, out, sizeof out, &outlen);
        check_int("after EE: WAIT_CERT", cl.state, TLS_ST_WAIT_CERT);
        tls_client_recv_handshake(&cl, cert, certlen, out, sizeof out, &outlen);
        check_int("after Cert: WAIT_CV", cl.state, TLS_ST_WAIT_CV);
        tls_client_recv_handshake(&cl, cv, cvlen, out, sizeof out, &outlen);
        check_int("after CV: WAIT_FINISHED", cl.state, TLS_ST_WAIT_FINISHED);

        int rc = tls_client_recv_handshake(&cl, sfin, sfinlen, out, sizeof out, &outlen);
        check_int("recv server Finished -> 0 (verified)", rc, 0);
        check_int("after Finished: CONNECTED", cl.state, TLS_ST_CONNECTED);
        check_int("after Finished: phase APPLICATION", cl.phase, TLS_PHASE_APPLICATION);
        check_int("client emitted its Finished", (outlen == 36 && out[0] == TLS_HS_FINISHED), 1);

        /* server verifies the client's Finished over Transcript(CH..server Finished) */
        uint8_t cfk[32], thash_sf[32];
        tls_finished_key(cfk, kss.client_hs_traffic);
        tls_transcript_hash(&ts, thash_sf);
        check_int("client Finished verifies server-side", tls_check_finished(cfk, thash_sf, out + 4), 0);

        /* application traffic secrets agree on both sides */
        uint8_t cap[32], sap[32];
        tls_derive_secret(cap, kss.master_secret, "c ap traffic", thash_sf);
        tls_derive_secret(sap, kss.master_secret, "s ap traffic", thash_sf);
        check_int("client ap secret agrees", memcmp(cl.client_ap_secret, cap, 32) == 0, 1);
        check_int("server ap secret agrees", memcmp(cl.server_ap_secret, sap, 32) == 0, 1);

        /* negative: a tampered server Finished must move the FSM to ERROR */
        tls_client c2; tls_client_init(&c2, "example.com", cpriv, crand);
        uint8_t ch2[1024]; tls_client_start(&c2, ch2, sizeof ch2);
        tls_client_recv_handshake(&c2, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, ee, eelen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, cert, certlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, cv, cvlen, out, sizeof out, &outlen);
        uint8_t badfin[64]; memcpy(badfin, sfin, sfinlen); badfin[4] ^= 1;
        check_int("tampered server Finished -> -1",
                  tls_client_recv_handshake(&c2, badfin, sfinlen, out, sizeof out, &outlen), -1);
        check_int("FSM enters ERROR", c2.state, TLS_ST_ERROR);

        /* negative: out-of-order message (EE while WAIT_SH) -> error */
        tls_client c3; tls_client_init(&c3, "example.com", cpriv, crand);
        uint8_t ch3[1024]; tls_client_start(&c3, ch3, sizeof ch3);
        check_int("unexpected EE in WAIT_SH -> -1",
                  tls_client_recv_handshake(&c3, ee, eelen, out, sizeof out, &outlen), -1);
    }

    printf("TLS 1.3 record binding (conn over the record layer):\n");
    {
        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+5); spriv[i]=(uint8_t)(0xA0+i);
                                crand[i]=(uint8_t)(0x33+i); srand[i]=(uint8_t)(0x44+i); }

        tls_conn cn;
        tls_conn_init(&cn, "example.com", cpriv, crand);
        check_int("init: rx epoch EARLY (plaintext)", cn.rx_phase, TLS_PHASE_EARLY);
        check_int("init: tx epoch EARLY (plaintext)", cn.tx_phase, TLS_PHASE_EARLY);

        /* ClientHello comes out as a plaintext handshake record */
        uint8_t crec[1100];
        int crl = tls_conn_start(&cn, crec, sizeof crec);
        check_int("start: plaintext handshake record", (crl > 5 && crec[0] == TLS_CONTENT_HANDSHAKE), 1);
        const uint8_t *ch = crec + 5; int chlen = crl - 5;   /* handshake message = record body */

        /* ---- server mirror: same transcript, same key schedule ---- */
        uint8_t spub[32], cpub[32];
        x25519_base(spub, spriv);
        x25519_base(cpub, cpriv);

        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256];
        int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);

        uint8_t hello_hash[32], ecdhe[32];
        tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss;
        tls_key_schedule_derive(&kss, ecdhe, hello_hash);

        /* server handshake epochs: write = server hs traffic, read = client hs traffic */
        tls_record_keys s_tx_hs, s_rx_hs;
        epoch_from_secret(&s_tx_hs, kss.server_hs_traffic);
        epoch_from_secret(&s_rx_hs, kss.client_hs_traffic);

        /* server flight: EE | Certificate | CertificateVerify | Finished */
        uint8_t ee[64], cert[64], cv[64];
        int eelen   = build_hs(ee,   TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        int certlen = build_hs(cert, TLS_HS_CERTIFICATE,          (const uint8_t*)"\x00\x00\x00\x00", 4);
        int cvlen   = build_hs(cv,   TLS_HS_CERTIFICATE_VERIFY,   (const uint8_t*)"\x08\x04\x00\x00", 4);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, cert, certlen);
        tls_transcript_update(&ts, cv, cvlen);

        uint8_t sfk[32], thash_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, thash_cv);              /* Transcript(CH..CV) */
        tls_finished_verify_data(svd, sfk, thash_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);
        tls_transcript_update(&ts, sfin, sfinlen);       /* Transcript(CH..server Finished) */

        /* coalesce the four messages into one record body */
        uint8_t flight[512]; int fl = 0;
        for (int i=0;i<eelen;i++)   flight[fl++] = ee[i];
        for (int i=0;i<certlen;i++) flight[fl++] = cert[i];
        for (int i=0;i<cvlen;i++)   flight[fl++] = cv[i];
        for (int i=0;i<sfinlen;i++) flight[fl++] = sfin[i];

        uint8_t out[256]; size_t outlen;

        /* 1) plaintext ServerHello record -> switch to the handshake epoch */
        uint8_t shrec[300];
        int shrl = plaintext_wrap(shrec, TLS_CONTENT_HANDSHAKE, sh, shlen);
        check_int("recv SH record -> OK", tls_conn_recv_record(&cn, shrec, shrl, out, sizeof out, &outlen), TLS_CONN_OK);
        check_int("phase anchor 1: rx HANDSHAKE", cn.rx_phase, TLS_PHASE_HANDSHAKE);
        check_int("phase anchor 1: tx HANDSHAKE", cn.tx_phase, TLS_PHASE_HANDSHAKE);
        check_int("handshake rx epoch seq starts at 0", (int)cn.rx.seq, 0);
        check_int("nothing emitted after SH", (int)outlen, 0);

        /* a ChangeCipherSpec between flights is ignored (middlebox compatibility) */
        uint8_t ccs[6] = { TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03,0x03, 0,1, 1 };
        check_int("CCS record ignored -> OK", tls_conn_recv_record(&cn, ccs, 6, out, sizeof out, &outlen), TLS_CONN_OK);
        check_int("CCS does not advance rx seq", (int)cn.rx.seq, 0);

        /* 2) one coalesced encrypted record carries EE..Finished -> CONNECTED */
        uint8_t srec[600];
        int srl = tls_record_seal(&s_tx_hs, TLS_CONTENT_HANDSHAKE, flight, fl, srec, sizeof srec);
        check_int("recv coalesced flight -> OK", tls_conn_recv_record(&cn, srec, srl, out, sizeof out, &outlen), TLS_CONN_OK);
        check_int("client CONNECTED", tls_conn_connected(&cn), 1);
        check_int("phase anchor 2: rx APPLICATION", cn.rx_phase, TLS_PHASE_APPLICATION);
        check_int("phase anchor 2: tx APPLICATION", cn.tx_phase, TLS_PHASE_APPLICATION);
        check_int("seq per epoch: app tx seq starts at 0", (int)cn.tx.seq, 0);
        check_int("emitted an encrypted Finished record", (outlen > 5 && out[0] == TLS_CONTENT_APPLICATION_DATA), 1);

        /* server opens the client Finished with client-handshake keys and verifies */
        uint8_t cfin[64], itype;
        int n = tls_record_open(&s_rx_hs, out, outlen, cfin, sizeof cfin, &itype);
        check_int("server opens client Finished", (n == 36 && itype == TLS_CONTENT_HANDSHAKE), 1);
        uint8_t cfk[32], thash_sf[32];
        tls_finished_key(cfk, kss.client_hs_traffic);
        tls_transcript_hash(&ts, thash_sf);
        check_int("client Finished verifies server-side", tls_check_finished(cfk, thash_sf, cfin + 4), 0);

        /* ---- application data both ways over the application epoch ---- */
        uint8_t s_cap[32], s_sap[32];
        tls_derive_secret(s_cap, kss.master_secret, "c ap traffic", thash_sf);
        tls_derive_secret(s_sap, kss.master_secret, "s ap traffic", thash_sf);
        tls_record_keys s_tx_ap, s_rx_ap;
        epoch_from_secret(&s_tx_ap, s_sap);     /* server writes app data */
        epoch_from_secret(&s_rx_ap, s_cap);     /* server reads client app data */

        const char *resp = "HTTP/1.1 200 OK"; size_t rlen = strlen(resp);
        char resphex[64]; tohex((const uint8_t*)resp, (int)rlen, resphex);
        uint8_t arec[256];
        int arl = tls_record_seal(&s_tx_ap, TLS_CONTENT_APPLICATION_DATA, (const uint8_t*)resp, rlen, arec, sizeof arec);
        uint8_t app[256]; size_t applen;
        check_int("recv server app data -> OK", tls_conn_recv_app(&cn, arec, arl, app, sizeof app, &applen), TLS_CONN_OK);
        check("decrypted server app data", app, (int)applen, resphex);

        const char *req = "GET / HTTP/1.1"; size_t qlen = strlen(req);
        char reqhex[64]; tohex((const uint8_t*)req, (int)qlen, reqhex);
        uint8_t qrec[256];
        int qrl = tls_conn_send_app(&cn, (const uint8_t*)req, qlen, qrec, sizeof qrec);
        check_int("send client app data", qrl > 5, 1);
        uint8_t srvplain[256], it2;
        int m = tls_record_open(&s_rx_ap, qrec, qrl, srvplain, sizeof srvplain, &it2);
        check_int("server opens client app data", (m == (int)qlen && it2 == TLS_CONTENT_APPLICATION_DATA), 1);
        check("server recovered client request", srvplain, m, reqhex);

        /* ---- invariant B: an AEAD failure is a transport error, not a handshake one ---- */
        tls_conn n1; tls_conn_init(&n1, "example.com", cpriv, crand);
        uint8_t r1[1100]; tls_conn_start(&n1, r1, sizeof r1);
        tls_conn_recv_record(&n1, shrec, shrl, out, sizeof out, &outlen);   /* now in HANDSHAKE */
        uint8_t bad[600]; for (int i=0;i<srl;i++) bad[i]=srec[i]; bad[7] ^= 1;  /* corrupt ciphertext */
        check_int("tampered encrypted record -> ERR_RECORD",
                  tls_conn_recv_record(&n1, bad, srl, out, sizeof out, &outlen), TLS_CONN_ERR_RECORD);
        check_int("AEAD failure leaves FSM intact (not ERROR)", n1.fsm.state != TLS_ST_ERROR, 1);
        check_int("FSM still expects the server flight (WAIT_EE)", n1.fsm.state, TLS_ST_WAIT_EE);

        /* ---- invariant B (other side): a real protocol failure DOES drive the FSM to ERROR ---- */
        tls_conn n2; tls_conn_init(&n2, "example.com", cpriv, crand);
        uint8_t r2[1100]; tls_conn_start(&n2, r2, sizeof r2);
        tls_conn_recv_record(&n2, shrec, shrl, out, sizeof out, &outlen);
        uint8_t badsvd[32]; for (int i=0;i<32;i++) badsvd[i]=svd[i]; badsvd[0] ^= 1;
        uint8_t badsfin[64]; int badsfinlen = build_hs(badsfin, TLS_HS_FINISHED, badsvd, 32);
        uint8_t flight2[512]; int fl2 = 0;
        for (int i=0;i<eelen;i++)      flight2[fl2++] = ee[i];
        for (int i=0;i<certlen;i++)    flight2[fl2++] = cert[i];
        for (int i=0;i<cvlen;i++)      flight2[fl2++] = cv[i];
        for (int i=0;i<badsfinlen;i++) flight2[fl2++] = badsfin[i];
        tls_record_keys s_tx_hs2; epoch_from_secret(&s_tx_hs2, kss.server_hs_traffic);
        uint8_t srec2[600];
        int srl2 = tls_record_seal(&s_tx_hs2, TLS_CONTENT_HANDSHAKE, flight2, fl2, srec2, sizeof srec2);
        check_int("valid record, bad Finished -> ERR_PROTOCOL",
                  tls_conn_recv_record(&n2, srec2, srl2, out, sizeof out, &outlen), TLS_CONN_ERR_PROTOCOL);
        check_int("protocol failure drives FSM to ERROR", n2.fsm.state, TLS_ST_ERROR);

        /* ---- invariant C: a handshake message fragmented across two records ---- */
        tls_conn n3; tls_conn_init(&n3, "example.com", cpriv, crand);
        uint8_t r3[1100]; tls_conn_start(&n3, r3, sizeof r3);
        tls_conn_recv_record(&n3, shrec, shrl, out, sizeof out, &outlen);
        tls_record_keys s_tx_hs3; epoch_from_secret(&s_tx_hs3, kss.server_hs_traffic);
        int split = eelen + 5;                          /* falls inside the Certificate message */
        uint8_t f1[600], f2[600]; size_t ol1, ol2;
        int f1l = tls_record_seal(&s_tx_hs3, TLS_CONTENT_HANDSHAKE, flight, split, f1, sizeof f1);
        int f2l = tls_record_seal(&s_tx_hs3, TLS_CONTENT_HANDSHAKE, flight + split, fl - split, f2, sizeof f2);
        check_int("fragment 1 -> OK, nothing emitted",
                  (tls_conn_recv_record(&n3, f1, f1l, out, sizeof out, &ol1) == TLS_CONN_OK && ol1 == 0), 1);
        check_int("after fragment 1: WAIT_CERT (partial Cert buffered)", n3.fsm.state, TLS_ST_WAIT_CERT);
        check_int("still not connected mid-message", tls_conn_connected(&n3), 0);
        check_int("fragment 2 -> OK, completes handshake",
                  (tls_conn_recv_record(&n3, f2, f2l, out, sizeof out, &ol2) == TLS_CONN_OK
                   && tls_conn_connected(&n3)), 1);
        check_int("reassembled flight emits the client Finished",
                  (ol2 > 5 && out[0] == TLS_CONTENT_APPLICATION_DATA), 1);
    }

    printf("TLS 1.3 Certificate message + PKI glue (RFC 8446 §4.4.2):\n");
    {
        uint8_t cad[512], leafd[512], rfcd[512];
        x509_cert ca, rfc;
        x509_parse(cad, unhex(T_CA_CERT, cad), &ca);
        x509_parse(rfcd, unhex(RFC_DER_CERT, rfcd), &rfc);
        int leaflen = unhex(T_LEAF_CERT, leafd);

        uint8_t certmsg[700];
        int cmlen = build_cert_msg(certmsg, leafd, leaflen);

        tls_cert_chain chain;
        check_int("Certificate message parses", tls_parse_certificate(certmsg, cmlen, &chain), 0);
        check_int("chain has one entry", (int)chain.count, 1);
        check_int("leaf subject CN == example.com", strcmp(chain.certs[0].subject_cn, "example.com") == 0, 1);

        uint64_t now2026 = 1767225600ULL;
        check_int("valid chain -> TLS_CERT_OK",
                  tls_verify_certificate_chain(&chain, "example.com", now2026, &ca, 1), TLS_CERT_OK);
        check_int("wildcard host -> TLS_CERT_OK",
                  tls_verify_certificate_chain(&chain, "foo.test.example", now2026, &ca, 1), TLS_CERT_OK);
        check_int("wrong host -> BAD_HOSTNAME",
                  tls_verify_certificate_chain(&chain, "evil.com", now2026, &ca, 1), TLS_CERT_BAD_HOSTNAME);
        check_int("expired -> EXPIRED",
                  tls_verify_certificate_chain(&chain, "example.com", 2050000000ULL, &ca, 1), TLS_CERT_EXPIRED);
        check_int("untrusted root -> UNTRUSTED",
                  tls_verify_certificate_chain(&chain, "example.com", now2026, &rfc, 1), TLS_CERT_UNTRUSTED);

        /* malformed: truncated Certificate message rejected */
        check_int("truncated Certificate message -> -1", tls_parse_certificate(certmsg, 6, &chain), -1);
    }

    printf("TLS 1.3 FSM certificate integration (trust gates WAIT_CERT):\n");
    {
        uint8_t cad[512]; x509_cert ca;
        x509_parse(cad, unhex(T_CA_CERT, cad), &ca);
        uint8_t leafd[512]; int leaflen = unhex(T_LEAF_CERT, leafd);
        uint8_t certmsg[700]; int cmlen = build_cert_msg(certmsg, leafd, leaflen);
        uint64_t now2026 = 1767225600ULL;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+7); spriv[i]=(uint8_t)(0xB0+i);
                                crand[i]=(uint8_t)(0x55+i); srand[i]=(uint8_t)(0x66+i); }
        uint8_t spub[32]; x25519_base(spub, spriv);
        uint8_t sh[256]; int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        uint8_t ee[64]; int eelen = build_hs(ee, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        uint8_t out[64]; size_t outlen;

        /* matching hostname: Certificate passes -> advance to WAIT_CV */
        tls_client cl; tls_client_init(&cl, "example.com", cpriv, crand);
        tls_client_set_trust(&cl, &ca, 1, now2026);
        uint8_t ch[1024]; tls_client_start(&cl, ch, sizeof ch);
        tls_client_recv_handshake(&cl, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, ee, eelen, out, sizeof out, &outlen);
        check_int("before cert: WAIT_CERT", cl.state, TLS_ST_WAIT_CERT);
        int rc = tls_client_recv_handshake(&cl, certmsg, cmlen, out, sizeof out, &outlen);
        check_int("trusted certificate -> WAIT_CV", (rc == 0 && cl.state == TLS_ST_WAIT_CV), 1);

        /* hostname mismatch: PKI fails -> FSM ERROR (cert now affects state) */
        tls_client c2; tls_client_init(&c2, "wrong.example", cpriv, crand);
        tls_client_set_trust(&c2, &ca, 1, now2026);
        uint8_t ch2[1024]; tls_client_start(&c2, ch2, sizeof ch2);
        tls_client_recv_handshake(&c2, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, ee, eelen, out, sizeof out, &outlen);
        int rc2 = tls_client_recv_handshake(&c2, certmsg, cmlen, out, sizeof out, &outlen);
        check_int("hostname mismatch -> -1 and ERROR", (rc2 == -1 && c2.state == TLS_ST_ERROR), 1);

        /* no trust store: certificate is accepted as transcript bytes (engine mode) */
        tls_client c3; tls_client_init(&c3, "example.com", cpriv, crand);
        uint8_t ch3[1024]; tls_client_start(&c3, ch3, sizeof ch3);
        tls_client_recv_handshake(&c3, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c3, ee, eelen, out, sizeof out, &outlen);
        int rc3 = tls_client_recv_handshake(&c3, certmsg, cmlen, out, sizeof out, &outlen);
        check_int("no trust store -> cert accepted -> WAIT_CV", (rc3 == 0 && c3.state == TLS_ST_WAIT_CV), 1);
    }

    printf(failures ? "\nTLS TEST: %d FAILURE(S)\n" : "\nTLS TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
