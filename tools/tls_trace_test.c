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
#include "x25519.h"

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
    check_ok("ServerHello parses (RFC bytes)", tls_parse_server_hello(sh, shlen, &suite, parsed_pub) == 0);
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

    printf(failures ? "\nTLS TRACE: %d FAILURE(S)\n" : "\nTLS TRACE: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
