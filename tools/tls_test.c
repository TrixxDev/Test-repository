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

    printf(failures ? "\nTLS TEST: %d FAILURE(S)\n" : "\nTLS TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
