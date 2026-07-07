/* RFC 8448 trace runner — replays the published "Simple 1-RTT Handshake" through
 * the tls/ engine and checks every derived value byte-for-byte against the RFC.
 * Build/run: `make tls-trace-test`.
 *
 * RFC 8448 negotiates TLS_AES_128_GCM_SHA256, while our record layer is
 * ChaCha20-Poly1305, so the trace's *encrypted records* cannot be opened by our
 * AEAD (that would need AES-GCM). The record layer is pinned separately (see
 * tls-test). What this runner validates is the cipher-independent protocol
 * engine on real RFC bytes: the transcript ordering, the X25519 ECDHE, the whole
 * key schedule, HKDF-Expand-Label (key/iv for both epochs) and the Finished
 * computation for both peers. Those are exactly the operations the FSM / conn
 * perform internally, so a byte-exact match here means the handshake math is
 * RFC-correct independent of certificates — letting the PKI layer be debugged on
 * its own later.
 *
 * Every constant below was extracted programmatically from rfc8448.txt (§3), not
 * transcribed by hand. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "transcript.h"
#include "key_schedule.h"
#include "handshake.h"
#include "cert.h"
#include "x509.h"
#include "x25519.h"
#include "sha256.h"
#include "client.h"

/* ---- RFC 8448 §3 values (verbatim) ---- */
#define RFC_CLIENT_PRIV       "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
#define RFC_CLIENT_PUB        "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
#define RFC_SERVER_PRIV       "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
#define RFC_SERVER_PUB        "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
#define RFC_CLIENTHELLO       "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
#define RFC_SERVERHELLO       "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
#define RFC_EE                "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000"
#define RFC_CERT              "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000"
#define RFC_CERTVERIFY        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3"
#define RFC_SERVER_FIN_VD     "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
#define RFC_CLIENT_FIN_VD     "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
#define RFC_ECDHE             "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
#define RFC_HELLO_HASH        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
#define RFC_EARLY_SECRET      "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
#define RFC_HANDSHAKE_SECRET  "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
#define RFC_MASTER_SECRET     "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
#define RFC_CLIENT_HS_TRAFFIC "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
#define RFC_SERVER_HS_TRAFFIC "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
#define RFC_SERVER_HS_KEY     "3fce516009c21727d0f2e4e86ee403bc"
#define RFC_SERVER_HS_IV      "5d313eb2671276ee13000b30"
#define RFC_CLIENT_HS_KEY     "dbfaa693d1762c5b666af5d950258d01"
#define RFC_CLIENT_HS_IV      "5bd3c71b836e0b76bb73265f"
#define RFC_THASH_SERVERFIN   "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
#define RFC_CLIENT_AP_TRAFFIC "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
#define RFC_SERVER_AP_TRAFFIC "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
#define RFC_SERVER_AP_KEY     "9f02283b6c9c07efc26bb9f2ac92e356"
#define RFC_SERVER_AP_IV      "cf782b88dd83549aadf1e984"
#define RFC_CLIENT_AP_KEY     "17422dda596ed5d9acd890e3c63f5051"
#define RFC_CLIENT_AP_IV      "5b78923dee08579033e523d9"

/* ---- RFC 8448 §4 "Resumed 0-RTT Handshake" values (verbatim) ----
 * Aurora doesn't implement 0-RTT (no early_data extension, no early traffic
 * keys -- see docs/SECURITY.md Step 15.7), so this section validates the
 * PSK/binder/resumption-secret math against the RFC's own published values,
 * not a byte-for-byte replay of its 0-RTT-capable ClientHello (which
 * necessarily differs in shape from ours). §3's master secret and
 * Transcript(CH..client Finished) feed the resumption_master_secret here,
 * exactly as the RFC's own narrative continues from §3 into §4. */
#define RFC_RES_PSK              "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"
#define RFC_RES_EARLY_SECRET     "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c"
#define RFC_RES_BINDER_KEY       "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256"
#define RFC_RES_FINISHED_KEY     "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa"
#define RFC_RES_PARTIAL_CH_HASH  "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"
#define RFC_RES_BINDER           "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"
#define RFC_S3_MASTER_SECRET     "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
#define RFC_S3_THASH_CLIENTFIN   "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"
#define RFC_RES_MASTER_SECRET    "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"

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

static void check(const char *name, const uint8_t *got, int n, const char *want)
{
    char hex[2048];
    tohex(got, n, hex);
    if (strcmp(hex, want) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n        got  %s\n        want %s\n", name, hex, want);
        failures++;
    }
}

static void check_ok(const char *name, int cond)
{
    if (cond) printf("  PASS  %s\n", name);
    else { printf("  FAIL  %s\n", name); failures++; }
}

/* declared length of a handshake message: 4-byte header + uint24 body */
static int hs_msg_len(const uint8_t *m) { return 4 + ((m[1] << 16) | (m[2] << 8) | m[3]); }

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

/* Build a generic handshake message: type | uint24(len) | body. */
static int build_hs(uint8_t *o, uint8_t type, const uint8_t *body, int blen)
{
    o[0] = type; o[1] = 0; o[2] = (uint8_t)(blen >> 8); o[3] = (uint8_t)blen;
    for (int i = 0; i < blen; i++) o[4 + i] = body[i];
    return 4 + blen;
}

/* Minimal PSK-accepting ServerHello: like a normal ServerHello but with an
 * extra pre_shared_key extension selecting identity 0 -- the signal that
 * tells the client (and this test) the abbreviated path was taken. */
static int build_server_hello_psk(uint8_t *o, const uint8_t random[32],
                                  uint16_t cipher, const uint8_t pub[32])
{
    int n = 0;
    o[n++] = TLS_HS_SERVER_HELLO; o[n++] = 0;
    int lenpos = n; n += 2;
    o[n++] = 0x03; o[n++] = 0x03;
    for (int i=0;i<32;i++) o[n++] = random[i];
    o[n++] = 32; for (int i=0;i<32;i++) o[n++] = 0;
    o[n++] = (uint8_t)(cipher>>8); o[n++] = (uint8_t)cipher;
    o[n++] = 0;
    int extpos = n; n += 2;
    o[n++]=0;o[n++]=43; o[n++]=0;o[n++]=2; o[n++]=0x03;o[n++]=0x04;
    o[n++]=0;o[n++]=51; o[n++]=0;o[n++]=36;
    o[n++]=0x00;o[n++]=0x1d; o[n++]=0;o[n++]=32; for(int i=0;i<32;i++) o[n++]=pub[i];
    /* pre_shared_key (41): selected_identity = 0 (uint16) -- presence alone
     * is what tls_parse_server_hello treats as "our PSK was accepted". */
    o[n++]=0;o[n++]=41; o[n++]=0;o[n++]=2; o[n++]=0;o[n++]=0;
    int extlen = n - extpos - 2;
    o[extpos] = (uint8_t)(extlen>>8); o[extpos+1] = (uint8_t)extlen;
    int body = n - 4;
    o[lenpos] = (uint8_t)(body>>8); o[lenpos+1] = (uint8_t)body;
    return n;
}

int main(void)
{
    uint8_t ch[256], sh[128], ee[64], cert[512], cv[160];
    int chlen   = unhex(RFC_CLIENTHELLO, ch);
    int shlen   = unhex(RFC_SERVERHELLO, sh);
    int eelen   = unhex(RFC_EE, ee);
    int certlen = unhex(RFC_CERT, cert);
    int cvlen   = unhex(RFC_CERTVERIFY, cv);

    printf("TLS 1.3 RFC 8448 trace — Simple 1-RTT Handshake:\n");

    /* --- ephemeral keys + ECDHE (our X25519 on the trace's private keys) --- */
    uint8_t cpriv[32], spriv[32], cpub[32], spub[32], ecdhe[32];
    unhex(RFC_CLIENT_PRIV, cpriv);
    unhex(RFC_SERVER_PRIV, spriv);
    x25519_base(cpub, cpriv);
    check("client public key  = X25519(client priv, 9)", cpub, 32, RFC_CLIENT_PUB);
    x25519_base(spub, spriv);
    check("server public key  = X25519(server priv, 9)", spub, 32, RFC_SERVER_PUB);
    x25519(ecdhe, cpriv, spub);
    check("ECDHE shared secret", ecdhe, 32, RFC_ECDHE);

    /* --- ServerHello parsed from the real RFC bytes --- */
    uint16_t suite = 0; uint8_t parsed_pub[32];
    check_ok("ClientHello well-formed (type/length)", ch[0] == TLS_HS_CLIENT_HELLO && hs_msg_len(ch) == chlen);
    check_ok("ServerHello parses (RFC bytes)", tls_parse_server_hello(sh, shlen, &suite, parsed_pub, 0) == 0);
    check_ok("ServerHello cipher == TLS_AES_128_GCM_SHA256 (0x1301)", suite == 0x1301);
    check("ServerHello key_share == server public key", parsed_pub, 32, RFC_SERVER_PUB);

    /* --- transcript through ClientHello..ServerHello --- */
    tls_transcript tr; tls_transcript_init(&tr);
    tls_transcript_update(&tr, ch, chlen);
    tls_transcript_update(&tr, sh, shlen);
    uint8_t hello_hash[32]; tls_transcript_hash(&tr, hello_hash);
    check("Transcript-Hash(ClientHello..ServerHello)", hello_hash, 32, RFC_HELLO_HASH);

    /* --- key schedule from ECDHE + hello hash --- */
    tls_key_schedule ks; tls_key_schedule_derive(&ks, ecdhe, hello_hash);
    check("Early secret",      ks.early_secret,     32, RFC_EARLY_SECRET);
    check("Handshake secret",  ks.handshake_secret, 32, RFC_HANDSHAKE_SECRET);
    check("Master secret",     ks.master_secret,    32, RFC_MASTER_SECRET);
    check("client handshake traffic secret", ks.client_hs_traffic, 32, RFC_CLIENT_HS_TRAFFIC);
    check("server handshake traffic secret", ks.server_hs_traffic, 32, RFC_SERVER_HS_TRAFFIC);

    /* --- handshake-epoch AEAD keys/IVs via HKDF-Expand-Label --- */
    uint8_t k[16], iv[12];
    tls_traffic_keys(ks.server_hs_traffic, k, 16, iv, 12);
    check("server handshake write key", k, 16, RFC_SERVER_HS_KEY);
    check("server handshake write iv",  iv, 12, RFC_SERVER_HS_IV);
    tls_traffic_keys(ks.client_hs_traffic, k, 16, iv, 12);
    check("client handshake write key", k, 16, RFC_CLIENT_HS_KEY);
    check("client handshake write iv",  iv, 12, RFC_CLIENT_HS_IV);

    /* --- server flight into the transcript (EE, Certificate, CertificateVerify) --- */
    check_ok("EncryptedExtensions type/length", ee[0] == TLS_HS_ENCRYPTED_EXTENSIONS && hs_msg_len(ee) == eelen);
    tls_transcript_update(&tr, ee, eelen);
    check_ok("Certificate type/length", cert[0] == TLS_HS_CERTIFICATE && hs_msg_len(cert) == certlen);
    tls_transcript_update(&tr, cert, certlen);
    check_ok("CertificateVerify type/length", cv[0] == TLS_HS_CERTIFICATE_VERIFY && hs_msg_len(cv) == cvlen);
    tls_transcript_update(&tr, cv, cvlen);

    /* --- server Finished over Transcript(CH..CertificateVerify) --- */
    uint8_t thash_cv[32]; tls_transcript_hash(&tr, thash_cv);
    uint8_t sfk[32], svd[32], rfc_svd[32];
    tls_finished_key(sfk, ks.server_hs_traffic);
    tls_finished_verify_data(svd, sfk, thash_cv);
    check("server Finished verify_data", svd, 32, RFC_SERVER_FIN_VD);
    unhex(RFC_SERVER_FIN_VD, rfc_svd);
    check_ok("our verifier accepts the server Finished", tls_check_finished(sfk, thash_cv, rfc_svd) == 0);

    /* append the server Finished message, then snapshot Transcript(CH..server Finished) */
    uint8_t sfin[36]; sfin[0] = TLS_HS_FINISHED; sfin[1] = 0; sfin[2] = 0; sfin[3] = 32;
    memcpy(sfin + 4, rfc_svd, 32);
    tls_transcript_update(&tr, sfin, 36);
    uint8_t thash_sf[32]; tls_transcript_hash(&tr, thash_sf);
    check("Transcript-Hash(ClientHello..server Finished)", thash_sf, 32, RFC_THASH_SERVERFIN);

    /* --- client Finished over the same transcript --- */
    uint8_t cfk[32], cvd[32];
    tls_finished_key(cfk, ks.client_hs_traffic);
    tls_finished_verify_data(cvd, cfk, thash_sf);
    check("client Finished verify_data", cvd, 32, RFC_CLIENT_FIN_VD);

    /* --- application traffic secrets + AEAD keys/IVs --- */
    uint8_t cap[32], sap[32];
    tls_derive_secret(cap, ks.master_secret, "c ap traffic", thash_sf);
    tls_derive_secret(sap, ks.master_secret, "s ap traffic", thash_sf);
    check("client application traffic secret", cap, 32, RFC_CLIENT_AP_TRAFFIC);
    check("server application traffic secret", sap, 32, RFC_SERVER_AP_TRAFFIC);
    tls_traffic_keys(sap, k, 16, iv, 12);
    check("server application write key", k, 16, RFC_SERVER_AP_KEY);
    check("server application write iv",  iv, 12, RFC_SERVER_AP_IV);
    tls_traffic_keys(cap, k, 16, iv, 12);
    check("client application write key", k, 16, RFC_CLIENT_AP_KEY);
    check("client application write iv",  iv, 12, RFC_CLIENT_AP_IV);

    printf("TLS 1.3 CertificateVerify — RFC 8448 (rsa_pss_rsae_sha256):\n");
    {
        /* the server's signature proves it holds the leaf private key, computed
         * over Transcript-Hash(ClientHello..Certificate) + the context string. */
        tls_transcript t2; tls_transcript_init(&t2);
        tls_transcript_update(&t2, ch, chlen);
        tls_transcript_update(&t2, sh, shlen);
        tls_transcript_update(&t2, ee, eelen);
        tls_transcript_update(&t2, cert, certlen);
        uint8_t th[32]; tls_transcript_hash(&t2, th);
        check("Transcript-Hash(ClientHello..Certificate)", th, 32,
              "764d6632b3c35c3f3205e3499ac3edbaabb88295fba751461d3678e2e5ea0687");

        tls_cert_chain chain;
        check_ok("Certificate message parses", tls_parse_certificate(cert, certlen, &chain) == 0);

        /* CertificateVerify body: SignatureScheme(2) | sig length(2) | signature */
        uint16_t scheme = (uint16_t)((cv[4] << 8) | cv[5]);
        size_t cvsiglen = (size_t)((cv[6] << 8) | cv[7]);
        const uint8_t *cvsig = cv + 8;
        check_ok("scheme == rsa_pss_rsae_sha256 (0x0804)", scheme == TLS_SIG_RSA_PSS_RSAE_SHA256);

        check_ok("CertificateVerify verifies under the leaf key",
                 tls_verify_certificate_verify(th, scheme, cvsig, cvsiglen,
                     chain.certs[0].spki_key.p, chain.certs[0].spki_key.len) == TLS_CV_OK);

        uint8_t badsig[256];
        for (size_t i = 0; i < cvsiglen; i++) badsig[i] = cvsig[i];
        badsig[0] ^= 1;
        check_ok("tampered CertificateVerify -> BAD",
                 tls_verify_certificate_verify(th, scheme, badsig, cvsiglen,
                     chain.certs[0].spki_key.p, chain.certs[0].spki_key.len) == TLS_CV_BAD);

        check_ok("wrong transcript -> BAD",
                 (th[0] ^= 1, tls_verify_certificate_verify(th, scheme, cvsig, cvsiglen,
                     chain.certs[0].spki_key.p, chain.certs[0].spki_key.len) == TLS_CV_BAD));

        /* 13.x.5 — dispatch is by SignatureScheme, not cert key type. Asking for
         * ecdsa_secp256r1_sha256 over an RSA leaf key: the key can't be decoded as
         * a P-256 point, so it fails verification (BAD) rather than being trusted. */
        check_ok("RSA key under ecdsa_secp256r1_sha256 -> BAD",
                 tls_verify_certificate_verify(th, TLS_SIG_ECDSA_SECP256R1_SHA256, cvsig, cvsiglen,
                     chain.certs[0].spki_key.p, chain.certs[0].spki_key.len) == TLS_CV_BAD);

        /* a genuinely unimplemented scheme (ed25519, 0x0807) is still UNSUPPORTED */
        check_ok("unimplemented scheme (ed25519) -> UNSUPPORTED",
                 tls_verify_certificate_verify(th, 0x0807, cvsig, cvsiglen,
                     chain.certs[0].spki_key.p, chain.certs[0].spki_key.len) == TLS_CV_UNSUPPORTED);
    }

    printf("TLS 1.3 RFC 8448 §4 — PSK / binder / resumption-secret math:\n");
    {
        /* --- pure key-schedule primitives, checked against the RFC's own §4
         * published values (same vectors already confirmed in a standalone
         * scratch harness before this test was wired in) --- */
        uint8_t psk[32]; unhex(RFC_RES_PSK, psk);
        uint8_t early[32]; tls_derive_early_secret(early, psk, sizeof psk);
        check("resumption Early Secret", early, 32, RFC_RES_EARLY_SECRET);

        uint8_t binder_key[32]; tls_derive_binder_key(binder_key, early);
        check("resumption binder_key = Derive-Secret(Early, \"res binder\", \"\")",
              binder_key, 32, RFC_RES_BINDER_KEY);

        uint8_t fk[32]; tls_finished_key(fk, binder_key);
        check("binder finished_key = HKDF-Expand-Label(binder_key, \"finished\")",
              fk, 32, RFC_RES_FINISHED_KEY);

        uint8_t prefix_hash[32]; unhex(RFC_RES_PARTIAL_CH_HASH, prefix_hash);
        uint8_t binder[32]; tls_finished_verify_data(binder, fk, prefix_hash);
        check("PSK binder = HMAC(finished_key, Transcript-Hash(truncated CH))",
              binder, 32, RFC_RES_BINDER);

        uint8_t ms[32]; unhex(RFC_S3_MASTER_SECRET, ms);
        uint8_t thash_cf[32]; unhex(RFC_S3_THASH_CLIENTFIN, thash_cf);
        uint8_t rms[32]; tls_derive_resumption_master_secret(rms, ms, thash_cf);
        check("resumption_master_secret = Derive-Secret(Master, \"res master\", Transcript(CH..client Fin))",
              rms, 32, RFC_RES_MASTER_SECRET);

        /* round-trip: a ticket_nonce of {0,0} reproduces the same PSK the
         * RFC started §4 from, closing the loop ticket -> PSK -> early secret */
        uint8_t nonce[2] = {0, 0};
        uint8_t ticket_psk[32]; tls_derive_ticket_psk(ticket_psk, rms, nonce, sizeof nonce);
        check("ticket_psk = HKDF-Expand-Label(res_master, \"resumption\", nonce) round-trips to the §4 PSK",
              ticket_psk, 32, RFC_RES_PSK);
    }

    printf("TLS 1.3 FSM — abbreviated (PSK-resumed) handshake (15.7):\n");
    {
        /* Synthetic, not an RFC-8448 byte replay: §4's own ClientHello is
         * 0-RTT-capable (carries an early_data extension Aurora doesn't
         * implement), so it cannot byte-match ours. This proves the FSM
         * wiring instead -- offer, accept, skip Cert/CV, reach CONNECTED --
         * using the RFC-verified PSK from the section above. */
        tls_session_ticket resume;
        unhex(RFC_RES_PSK, resume.psk);
        resume.lifetime_secs = 7200;
        resume.age_add = 0xfeedface;
        resume.obtained_ms = 1000;
        static const uint8_t tk[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
        for (size_t i = 0; i < sizeof tk; i++) resume.ticket[i] = tk[i];
        resume.ticket_len = sizeof tk;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+3); spriv[i]=(uint8_t)(0xA0+i);
                                crand[i]=(uint8_t)(0x11+i); srand[i]=(uint8_t)(0x22+i); }
        uint8_t spub[32], cpub[32]; x25519_base(spub, spriv); x25519_base(cpub, cpriv);

        tls_client cl; tls_client_init(&cl, "example.com", cpriv, crand);
        tls_client_offer_psk(&cl, &resume, 4000);
        uint8_t chb[1024]; int chblen = tls_client_start(&cl, chb, sizeof chb);
        check_ok("resumed ClientHello built", chblen > 0);

        uint8_t ext45[] = { 0, 45 }, ext41[] = { 0, 41 };
        check_ok("resumed ClientHello offers psk_key_exchange_modes (45)",
                 contains(chb, (size_t)chblen, ext45, sizeof ext45));
        check_ok("resumed ClientHello offers pre_shared_key (41)",
                 contains(chb, (size_t)chblen, ext41, sizeof ext41));
        check_ok("resumed ClientHello carries the cached ticket bytes",
                 contains(chb, (size_t)chblen, tk, sizeof tk));

        /* independently recompute the embedded binder and compare -- proves
         * tls_build_client_hello's patched-in HMAC is self-consistent, since
         * an RFC-literal byte match isn't reachable (0-RTT shape mismatch) */
        uint8_t exp_early[32]; tls_derive_early_secret(exp_early, resume.psk, sizeof resume.psk);
        uint8_t exp_binder_key[32]; tls_derive_binder_key(exp_binder_key, exp_early);
        uint8_t exp_fk[32]; tls_finished_key(exp_fk, exp_binder_key);
        uint8_t exp_prefix_hash[32]; sha256(chb, (size_t)(chblen - 35), exp_prefix_hash);
        uint8_t exp_binder[32]; tls_finished_verify_data(exp_binder, exp_fk, exp_prefix_hash);
        char exp_binder_hex[65]; tohex(exp_binder, 32, exp_binder_hex);
        check("embedded PSK binder matches an independent recomputation",
              chb + chblen - 32, 32, exp_binder_hex);

        /* --- drive the abbreviated handshake to CONNECTED: a synthetic
         * loopback "server" that accepts the PSK, mirroring the pattern the
         * full-handshake FSM tests already use for their server side --- */
        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, chb, (size_t)chblen);
        uint8_t shb[256]; int shblen = build_server_hello_psk(shb, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, shb, (size_t)shblen);

        uint8_t hello_hash[32]; tls_transcript_hash(&ts, hello_hash);
        uint8_t ecdhe[32]; x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss; tls_key_schedule_derive_from_early(&kss, exp_early, ecdhe, hello_hash);

        uint8_t eeb[64]; int eeblen = build_hs(eeb, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        tls_transcript_update(&ts, eeb, (size_t)eeblen);

        /* server Finished over Transcript(CH..EE) -- no Certificate/CV in a
         * resumed handshake (RFC 8446 §2.2) */
        uint8_t sfk[32], th_ee[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, th_ee);
        tls_finished_verify_data(svd, sfk, th_ee);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);

        uint8_t out[64]; size_t outlen;
        int rc_sh = tls_client_recv_handshake(&cl, shb, (size_t)shblen, out, sizeof out, &outlen);
        check_ok("PSK ServerHello accepted", rc_sh == 0);
        check_ok("client recognizes the PSK as accepted", cl.psk_accepted == 1);

        int rc_ee = tls_client_recv_handshake(&cl, eeb, (size_t)eeblen, out, sizeof out, &outlen);
        check_ok("resumed EncryptedExtensions -> WAIT_FINISHED directly (Cert/CV skipped)",
                 rc_ee == 0 && cl.state == TLS_ST_WAIT_FINISHED);

        int rc_fin = tls_client_recv_handshake(&cl, sfin, (size_t)sfinlen, out, sizeof out, &outlen);
        check_ok("resumed Finished accepted -> CONNECTED", rc_fin == 0 && cl.state == TLS_ST_CONNECTED);
        check_ok("resumed handshake authenticates the peer (PSK possession)", cl.peer_authenticated == 1);
        check_ok("client emitted its own Finished", out[0] == TLS_HS_FINISHED && outlen == 36);
        check_ok("a new resumption_master_secret is ready for a future ticket", cl.has_resumption_secret == 1);
    }

    printf(failures ? "\nTLS TRACE: %d FAILURE(S)\n" : "\nTLS TRACE: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
