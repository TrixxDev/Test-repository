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
#include "record_reader.h"
#include "transcript.h"
#include "key_schedule.h"
#include "handshake.h"
#include "client.h"
#include "conn.h"
#include "driver.h"
#include "cert.h"
#include "x509.h"
#include "verify_cert.h"
#include "chacha20poly1305.h"
#include "x25519.h"
#include "sha256.h"
#include "mgf1.h"
#include "bignum.h"

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

/* Build a raw TLS record (5-byte header + body) for the framing tests. Body is a
 * deterministic ramp so the returned bytes can be checked. Returns total length. */
static int mk_record(uint8_t *o, uint8_t ctype, int bodylen)
{
    o[0] = ctype; o[1] = 0x03; o[2] = 0x03;
    o[3] = (uint8_t)(bodylen >> 8); o[4] = (uint8_t)bodylen;
    for (int i = 0; i < bodylen; i++) o[5 + i] = (uint8_t)(i * 7 + ctype);
    return 5 + bodylen;
}

/* trace sink: record the event sequence for assertions */
static tls_event g_ev[64]; static int g_evn;
static void rec_sink(void *ctx, tls_event ev, uint32_t detail) { (void)ctx; (void)detail; if (g_evn < 64) g_ev[g_evn++] = ev; }

/* Mock byte transport for the handshake driver: serves a pre-built server flight
 * (`in`) to read() in configurable chunks and captures everything write() sends
 * (`out`). This is how the record-stream handling is proven off the wire —
 * adversarial fragmentation lives entirely in the read schedule, not in TLS. */
typedef struct {
    const uint8_t *in; int in_len, in_pos;
    int first_read;     /* if >0, the FIRST read returns exactly this many bytes */
    int read_chunk;     /* then up to this per read (0 = all remaining)          */
    int first_done;
    int write_chunk;    /* up to this per write (0 = all) — forces send_all loops */
    uint8_t out[2048]; int out_len;
} mockx;

static int mx_read(void *ctx, uint8_t *buf, size_t cap)
{
    mockx *m = (mockx *)ctx;
    int remaining = m->in_len - m->in_pos;
    if (remaining <= 0) return 0;                       /* clean EOF */
    int n = remaining;
    if (m->first_read > 0 && !m->first_done) { n = m->first_read; m->first_done = 1; }
    else if (m->read_chunk > 0 && n > m->read_chunk)   n = m->read_chunk;
    if ((size_t)n > cap) n = (int)cap;
    for (int i = 0; i < n; i++) buf[i] = m->in[m->in_pos + i];
    m->in_pos += n;
    return n;
}

static int mx_write(void *ctx, const uint8_t *buf, size_t len)
{
    mockx *m = (mockx *)ctx;
    int n = (int)len;
    if (m->write_chunk > 0 && n > m->write_chunk) n = m->write_chunk;
    if (m->out_len + n > (int)sizeof m->out) n = (int)sizeof m->out - m->out_len;
    for (int i = 0; i < n; i++) m->out[m->out_len + i] = buf[i];
    m->out_len += n;
    return n;
}

/* Run the driver to CONNECTED over the mock transport. The conn/reader are static
 * (large) to keep the stack small; caller pre-sets mx->{first_read,read_chunk,
 * write_chunk}. Trust + trace are installed so the milestone trace is recorded. */
static int drive_once(tls_conn *cn, tls_record_reader *rd,
                      const uint8_t *cpriv, const uint8_t *crand,
                      const x509_cert *ca, uint64_t now,
                      const uint8_t *stream, int streamlen, mockx *mx)
{
    static uint8_t scratch[2048];
    tls_conn_init(cn, "example.com", cpriv, crand);
    tls_client_set_trust(&cn->fsm, ca, 1, now);
    g_evn = 0; tls_conn_set_trace(cn, rec_sink, 0);
    tls_reader_init(rd);
    mx->in = stream; mx->in_len = streamlen; mx->in_pos = 0; mx->first_done = 0; mx->out_len = 0;
    tls_transport t = { mx_read, mx_write, mx };
    return tls_driver_handshake(cn, rd, &t, scratch, sizeof scratch);
}

/* The full client-visible milestone trace, in order, for a clean handshake. */
static int milestones_ok(void)
{
    static const tls_event want[] = {
        TLS_EV_CLIENT_HELLO_SENT, TLS_EV_SERVER_HELLO, TLS_EV_HANDSHAKE_KEYS,
        TLS_EV_ENCRYPTED_EXTENSIONS, TLS_EV_CERTIFICATE, TLS_EV_CERT_CHAIN_OK,
        TLS_EV_CERT_VERIFY_OK, TLS_EV_PEER_AUTHENTICATED, TLS_EV_FINISHED_OK,
        TLS_EV_APP_KEYS, TLS_EV_CONNECTED
    };
    int n = (int)(sizeof want / sizeof want[0]);
    if (g_evn != n) return 0;
    for (int i = 0; i < n; i++) if (g_ev[i] != want[i]) return 0;
    return 1;
}

/* Test-only "server" side: sign a CertificateVerify with the leaf private key via
 * RSASSA-PSS (EMSA-PSS-ENCODE + modexp). The library is verify-only; this mirrors
 * how the loopback test computes the server Finished. `th` is Transcript-Hash(CH..
 * Certificate). Returns the CertificateVerify handshake message length. */
static int pss_sign_cv(uint8_t *cvmsg, const uint8_t th[32],
                       const uint8_t *n, int nlen, const uint8_t *d, int dlen)
{
    /* signed content = 0x20 x64 || context || 0x00 || transcript_hash; mHash = SHA-256 */
    uint8_t content[64 + 33 + 1 + 32]; int o = 0;
    for (int i = 0; i < 64; i++) content[o++] = 0x20;
    const char *ctx = "TLS 1.3, server CertificateVerify";
    for (int i = 0; ctx[i]; i++) content[o++] = (uint8_t)ctx[i];
    content[o++] = 0;
    for (int i = 0; i < 32; i++) content[o++] = th[i];
    uint8_t mh[32]; sha256(content, o, mh);

    bignum N; bignum_from_bytes(&N, n, nlen);
    size_t modbits = bignum_bitlen(&N), embits = modbits - 1, emlen = (embits + 7) / 8;
    uint8_t salt[32]; for (int i = 0; i < 32; i++) salt[i] = (uint8_t)i;

    /* H = SHA-256(0x00 x8 || mHash || salt) */
    uint8_t mprime[8 + 32 + 32];
    for (int i = 0; i < 8; i++) mprime[i] = 0;
    for (int i = 0; i < 32; i++) mprime[8 + i] = mh[i];
    for (int i = 0; i < 32; i++) mprime[40 + i] = salt[i];
    uint8_t H[32]; sha256(mprime, sizeof mprime, H);

    /* DB = PS(0) || 0x01 || salt, masked with MGF1(H); EM = maskedDB || H || 0xbc */
    size_t dblen = emlen - 32 - 1;
    uint8_t db[256]; for (size_t i = 0; i < dblen; i++) db[i] = 0;
    db[dblen - 33] = 0x01; for (int i = 0; i < 32; i++) db[dblen - 32 + i] = salt[i];
    uint8_t mask[256]; mgf1_sha256(H, 32, mask, dblen);
    for (size_t i = 0; i < dblen; i++) db[i] ^= mask[i];
    size_t lead = 8 * emlen - embits; if (lead) db[0] &= (uint8_t)(0xff >> lead);
    uint8_t em[256]; for (size_t i = 0; i < dblen; i++) em[i] = db[i];
    for (int i = 0; i < 32; i++) em[dblen + i] = H[i]; em[emlen - 1] = 0xbc;

    /* sig = em^d mod n */
    bignum EM, D, SIG; bignum_from_bytes(&EM, em, emlen); bignum_from_bytes(&D, d, dlen);
    bignum_modexp(&SIG, &EM, &D, &N);
    uint8_t sig[256]; bignum_to_bytes(&SIG, sig, (size_t)nlen);

    int body = 2 + 2 + nlen;
    cvmsg[0] = TLS_HS_CERTIFICATE_VERIFY; cvmsg[1] = 0;
    cvmsg[2] = (uint8_t)(body >> 8); cvmsg[3] = (uint8_t)body;
    cvmsg[4] = 0x08; cvmsg[5] = 0x04;                       /* rsa_pss_rsae_sha256 */
    cvmsg[6] = (uint8_t)(nlen >> 8); cvmsg[7] = (uint8_t)nlen;
    for (int i = 0; i < nlen; i++) cvmsg[8 + i] = sig[i];
    return 8 + nlen;
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

/* Build a Certificate message carrying several certs (a realistic leaf+CA chain),
 * each as its own CertificateEntry with empty extensions. */
static int build_cert_msg_n(uint8_t *o, const uint8_t *const ders[], const int lens[], int ncerts)
{
    int n = 0;
    o[n++] = TLS_HS_CERTIFICATE; o[n++] = 0; o[n++] = 0; o[n++] = 0;   /* len patched below */
    o[n++] = 0;                                                        /* request context: empty */
    int listlen = 0;
    for (int i = 0; i < ncerts; i++) listlen += 3 + lens[i] + 2;
    o[n++] = (uint8_t)(listlen >> 16); o[n++] = (uint8_t)(listlen >> 8); o[n++] = (uint8_t)listlen;
    for (int i = 0; i < ncerts; i++) {
        o[n++] = (uint8_t)(lens[i] >> 16); o[n++] = (uint8_t)(lens[i] >> 8); o[n++] = (uint8_t)lens[i];
        for (int j = 0; j < lens[i]; j++) o[n++] = ders[i][j];
        o[n++] = 0; o[n++] = 0;                                        /* entry extensions: empty */
    }
    int body = n - 4;
    o[1] = (uint8_t)(body >> 16); o[2] = (uint8_t)(body >> 8); o[3] = (uint8_t)body;
    return n;
}

/* an unrelated self-signed RSA certificate (RFC 8448 §3) — a "wrong" root */
#define RFC_DER_CERT "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1"

/* synthetic 1024-bit CA (self-signed) + leaf signed by it, with the leaf's
 * private key so the test can play "server" and sign CertificateVerify (the
 * library itself is verify-only). From tools/mkchain. */
#define T_CA_CERT   "308201a63082010fa003020102020101300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3019311730150603550403130e4175726f7261205465737420434130819f300d06092a864886f70d010101050003818d0030818902818100914dc084000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007732cf66ae551d9f99d4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054abb024451f79ca150203010001300d06092a864886f70d01010b0500038181005aa1a47ee6e84e6bbe29bcb16207087ecfccdbc66214a6c372379ba64d43212d6a496094f564ffe12686ec80517c213d7cc7a295d5efe29917527f36f29599d87031603b8f880864c21fb0fc6723f122230faa66ad05ef17189079508995c42f7aad0850a3844a157ba21a6d0952a4a294bd418a56219eecd1a3430b0fe7323f"
#define T_LEAF_CERT "308201e030820149a003020102020102300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d30819f300d06092a864886f70d010101050003818d00308189028181008e67a321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007600e22250a7f8ade8900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282c15e8195233abef0203010001a33b303930370603551d110430302e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d820e2a2e746573742e6578616d706c65300d06092a864886f70d01010b050003818100480244df1797489d5f5dd3e84f7f0cbdc9a6f573f22ea7825feccf7a3c13f500e04119491314baa8853e90f5a449d398b8e34e3bf75df7f436d79382d32734978e44870f65c47064c95843197cd8e44b36b6cd6f69753bb33401e9d90a3256965d0a46d199586cf7c6b836a443460995663c4501034f40dd46816071e9d8f951"
#define T_LEAF_N    "8e67a321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007600e22250a7f8ade8900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282c15e8195233abef"
#define T_LEAF_D    "22fe92d6e4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bcde4321bce01319c60846392b7840cb3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3f54c0ab3ff045cf9d0b07a7781"

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

    printf("TLS 1.3 authenticated handshake (Cert + CertificateVerify + Finished):\n");
    {
        uint8_t cad[700]; x509_cert ca;
        x509_parse(cad, unhex(T_CA_CERT, cad), &ca);
        uint8_t leafd[700]; int leaflen = unhex(T_LEAF_CERT, leafd);
        uint8_t certmsg[800]; int cmlen = build_cert_msg(certmsg, leafd, leaflen);
        uint8_t ln[128], ld[128];
        int lnlen = unhex(T_LEAF_N, ln), ldlen = unhex(T_LEAF_D, ld);
        uint64_t now2026 = 1767225600ULL;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+9); spriv[i]=(uint8_t)(0xC0+i);
                                crand[i]=(uint8_t)(0x77+i); srand[i]=(uint8_t)(0x88+i); }
        uint8_t spub[32], cpub[32]; x25519_base(spub, spriv); x25519_base(cpub, cpriv);

        tls_client cl; tls_client_init(&cl, "example.com", cpriv, crand);
        tls_client_set_trust(&cl, &ca, 1, now2026);
        uint8_t ch[1024]; int chlen = tls_client_start(&cl, ch, sizeof ch);

        /* server mirror: transcript + handshake keys */
        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256]; int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);
        uint8_t hello_hash[32], ecdhe[32]; tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss; tls_key_schedule_derive(&kss, ecdhe, hello_hash);

        uint8_t ee[64]; int eelen = build_hs(ee, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, certmsg, cmlen);

        /* forge a real CertificateVerify over Transcript(CH..Certificate) */
        uint8_t th_cert[32]; tls_transcript_hash(&ts, th_cert);
        uint8_t cvmsg[256]; int cvlen = pss_sign_cv(cvmsg, th_cert, ln, lnlen, ld, ldlen);
        tls_transcript_update(&ts, cvmsg, cvlen);

        /* server Finished over Transcript(CH..CertificateVerify) */
        uint8_t sfk[32], th_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, th_cv);
        tls_finished_verify_data(svd, sfk, th_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);

        uint8_t out[64]; size_t outlen;
        tls_client_recv_handshake(&cl, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, ee, eelen, out, sizeof out, &outlen);
        int rcc = tls_client_recv_handshake(&cl, certmsg, cmlen, out, sizeof out, &outlen);
        check_int("Certificate accepted -> WAIT_CV", (rcc == 0 && cl.state == TLS_ST_WAIT_CV), 1);
        check_int("not authenticated after Certificate alone", cl.peer_authenticated, 0);
        int rcv = tls_client_recv_handshake(&cl, cvmsg, cvlen, out, sizeof out, &outlen);
        check_int("CertificateVerify accepted -> WAIT_FINISHED", (rcv == 0 && cl.state == TLS_ST_WAIT_FINISHED), 1);
        check_int("peer_authenticated set only after CV", cl.peer_authenticated, 1);
        int rcf = tls_client_recv_handshake(&cl, sfin, sfinlen, out, sizeof out, &outlen);
        check_int("Finished accepted -> CONNECTED", (rcf == 0 && cl.state == TLS_ST_CONNECTED), 1);
        check_int("CONNECTED implies authenticated", (tls_client_connected(&cl) && cl.peer_authenticated), 1);

        /* error separation: tampered CertificateVerify -> AUTH_ERROR */
        tls_client c2; tls_client_init(&c2, "example.com", cpriv, crand);
        tls_client_set_trust(&c2, &ca, 1, now2026);
        uint8_t ch2[1024]; tls_client_start(&c2, ch2, sizeof ch2);
        tls_client_recv_handshake(&c2, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, ee, eelen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, certmsg, cmlen, out, sizeof out, &outlen);
        uint8_t badcv[256]; memcpy(badcv, cvmsg, cvlen); badcv[8] ^= 1;   /* flip a signature byte */
        int rb = tls_client_recv_handshake(&c2, badcv, cvlen, out, sizeof out, &outlen);
        check_int("tampered CV -> AUTH error, not authenticated",
                  (rb == -1 && c2.state == TLS_ST_ERROR && c2.error == TLS_ERR_AUTH && c2.peer_authenticated == 0), 1);

        /* snapshot proof: a CV signed over the wrong transcript (CH..SH) is rejected,
         * pinning the FSM's snapshot boundary to exactly CH..Certificate */
        tls_client c3; tls_client_init(&c3, "example.com", cpriv, crand);
        tls_client_set_trust(&c3, &ca, 1, now2026);
        uint8_t ch3[1024]; tls_client_start(&c3, ch3, sizeof ch3);
        tls_client_recv_handshake(&c3, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c3, ee, eelen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c3, certmsg, cmlen, out, sizeof out, &outlen);
        uint8_t wrongcv[256]; int wlen = pss_sign_cv(wrongcv, hello_hash, ln, lnlen, ld, ldlen);
        int rw = tls_client_recv_handshake(&c3, wrongcv, wlen, out, sizeof out, &outlen);
        check_int("CV over wrong transcript snapshot -> AUTH error", (rw == -1 && c3.error == TLS_ERR_AUTH), 1);

        /* error separation: bad certificate (hostname) -> CERT_ERROR */
        tls_client c4; tls_client_init(&c4, "wrong.example", cpriv, crand);
        tls_client_set_trust(&c4, &ca, 1, now2026);
        uint8_t ch4[1024]; tls_client_start(&c4, ch4, sizeof ch4);
        tls_client_recv_handshake(&c4, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c4, ee, eelen, out, sizeof out, &outlen);
        int rh = tls_client_recv_handshake(&c4, certmsg, cmlen, out, sizeof out, &outlen);
        check_int("bad hostname -> CERT error (before any CV)", (rh == -1 && c4.error == TLS_ERR_CERT), 1);
    }

    printf("TLS 1.3 handshake trace (event milestones):\n");
    {
        uint8_t cad[700]; x509_cert ca;
        x509_parse(cad, unhex(T_CA_CERT, cad), &ca);
        uint8_t leafd[700]; int leaflen = unhex(T_LEAF_CERT, leafd);
        uint8_t certmsg[800]; int cmlen = build_cert_msg(certmsg, leafd, leaflen);
        uint8_t ln[128], ld[128]; int lnlen = unhex(T_LEAF_N, ln), ldlen = unhex(T_LEAF_D, ld);
        uint64_t now2026 = 1767225600ULL;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+13); spriv[i]=(uint8_t)(0xD0+i);
                                crand[i]=(uint8_t)(0x99+i); srand[i]=(uint8_t)(0xAA+i); }
        uint8_t spub[32], cpub[32]; x25519_base(spub, spriv); x25519_base(cpub, cpriv);

        tls_client cl; tls_client_init(&cl, "example.com", cpriv, crand);
        tls_client_set_trust(&cl, &ca, 1, now2026);
        g_evn = 0; tls_client_set_trace(&cl, rec_sink, 0);
        uint8_t ch[1024]; int chlen = tls_client_start(&cl, ch, sizeof ch);

        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256]; int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);
        uint8_t hello_hash[32], ecdhe[32]; tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss; tls_key_schedule_derive(&kss, ecdhe, hello_hash);
        uint8_t ee[64]; int eelen = build_hs(ee, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, certmsg, cmlen);
        uint8_t th_cert[32]; tls_transcript_hash(&ts, th_cert);
        uint8_t cvmsg[256]; int cvlen = pss_sign_cv(cvmsg, th_cert, ln, lnlen, ld, ldlen);
        tls_transcript_update(&ts, cvmsg, cvlen);
        uint8_t sfk[32], th_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, th_cv);
        tls_finished_verify_data(svd, sfk, th_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);

        uint8_t out[64]; size_t outlen;
        tls_client_recv_handshake(&cl, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, ee, eelen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, certmsg, cmlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, cvmsg, cvlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&cl, sfin, sfinlen, out, sizeof out, &outlen);

        tls_event want[] = {
            TLS_EV_CLIENT_HELLO_SENT, TLS_EV_SERVER_HELLO, TLS_EV_HANDSHAKE_KEYS,
            TLS_EV_ENCRYPTED_EXTENSIONS, TLS_EV_CERTIFICATE, TLS_EV_CERT_CHAIN_OK,
            TLS_EV_CERT_VERIFY_OK, TLS_EV_PEER_AUTHENTICATED, TLS_EV_FINISHED_OK,
            TLS_EV_APP_KEYS, TLS_EV_CONNECTED
        };
        int nwant = (int)(sizeof want / sizeof want[0]);
        int seq_ok = (g_evn == nwant);
        for (int i = 0; i < nwant && seq_ok; i++) if (g_ev[i] != want[i]) seq_ok = 0;
        check_int("trace emits the full milestone sequence", seq_ok, 1);
        check_int("event names are available", tls_event_name(TLS_EV_CONNECTED)[0] != 0, 1);

        /* failure path: tampered CertificateVerify ends the trace at FAIL_AUTH */
        tls_client c2; tls_client_init(&c2, "example.com", cpriv, crand);
        tls_client_set_trust(&c2, &ca, 1, now2026);
        g_evn = 0; tls_client_set_trace(&c2, rec_sink, 0);
        uint8_t ch2[1024]; tls_client_start(&c2, ch2, sizeof ch2);
        tls_client_recv_handshake(&c2, sh, shlen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, ee, eelen, out, sizeof out, &outlen);
        tls_client_recv_handshake(&c2, certmsg, cmlen, out, sizeof out, &outlen);
        uint8_t badcv[256]; memcpy(badcv, cvmsg, cvlen); badcv[8] ^= 1;
        tls_client_recv_handshake(&c2, badcv, cvlen, out, sizeof out, &outlen);
        check_int("failure trace ends at FAIL_AUTH", (g_evn > 0 && g_ev[g_evn-1] == TLS_EV_FAIL_AUTH), 1);
    }

    printf("TLS 1.3 record reader (byte stream -> records):\n");
    {
        tls_record_reader rr;
        const uint8_t *rec; size_t rl;

        /* 1. header delivered one byte at a time, then body one byte at a time */
        uint8_t r1[64]; int r1n = mk_record(r1, 0x16, 10);
        tls_reader_init(&rr);
        int got = 0;
        for (int i = 0; i < r1n; i++) {
            tls_reader_feed(&rr, &r1[i], 1);
            int rc = tls_reader_next(&rr, &rec, &rl);
            if (rc == 1) { got = (rl == (size_t)r1n && memcmp(rec, r1, r1n) == 0); }
            else if (i < r1n - 1) { if (rc != 0) got = -1; }   /* must say "need more" until last byte */
        }
        check_int("1. header+body byte-by-byte reassembles one record", got, 1);
        check_int("   nothing left pending", (int)tls_reader_pending(&rr), 0);

        /* 2. body byte-by-byte after a whole header */
        uint8_t r2[64]; int r2n = mk_record(r2, 0x17, 8);
        tls_reader_init(&rr);
        tls_reader_feed(&rr, r2, 5);                       /* whole header */
        check_int("2. header alone -> need more", tls_reader_next(&rr, &rec, &rl), 0);
        int ok2 = 1;
        for (int i = 5; i < r2n; i++) {
            tls_reader_feed(&rr, &r2[i], 1);
            int rc = tls_reader_next(&rr, &rec, &rl);
            if (i < r2n - 1) ok2 &= (rc == 0);
            else ok2 &= (rc == 1 && rl == (size_t)r2n && memcmp(rec, r2, r2n) == 0);
        }
        check_int("2. body byte-by-byte completes the record", ok2, 1);

        /* 3. two records in one chunk -> two records out */
        uint8_t a[64], b[64], chunk[128];
        int an = mk_record(a, 0x16, 6), bn = mk_record(b, 0x17, 9);
        memcpy(chunk, a, an); memcpy(chunk + an, b, bn);
        tls_reader_init(&rr);
        tls_reader_feed(&rr, chunk, an + bn);
        int t3 = (tls_reader_next(&rr, &rec, &rl) == 1 && rl == (size_t)an && memcmp(rec, a, an) == 0);
        t3 &= (tls_reader_next(&rr, &rec, &rl) == 1 && rl == (size_t)bn && memcmp(rec, b, bn) == 0);
        t3 &= (tls_reader_next(&rr, &rec, &rl) == 0);
        check_int("3. two coalesced records split into two", t3, 1);

        /* 4. boundary inside the second record's header */
        tls_reader_init(&rr);
        tls_reader_feed(&rr, a, an);                       /* record 1 */
        tls_reader_feed(&rr, b, 2);                        /* first 2 bytes of record 2's header */
        int t4 = (tls_reader_next(&rr, &rec, &rl) == 1 && memcmp(rec, a, an) == 0);
        t4 &= (tls_reader_next(&rr, &rec, &rl) == 0);      /* partial header -> need more */
        tls_reader_feed(&rr, b + 2, bn - 2);              /* rest of record 2 */
        t4 &= (tls_reader_next(&rr, &rec, &rl) == 1 && rl == (size_t)bn && memcmp(rec, b, bn) == 0);
        check_int("4. split inside the 2nd record header reassembles", t4, 1);

        /* 5. zero-length body is a valid 5-byte record */
        uint8_t z[8]; int zn = mk_record(z, 0x15, 0);
        tls_reader_init(&rr);
        tls_reader_feed(&rr, z, zn);
        check_int("5. zero-length body -> 5-byte record",
                  (tls_reader_next(&rr, &rec, &rl) == 1 && rl == 5), 1);

        /* 6. length limit: max body accepted (waits for body), one over -> error */
        uint8_t hmax[5] = { 0x17, 0x03, 0x03, (TLS_RECORD_MAX_BODY >> 8), (TLS_RECORD_MAX_BODY & 0xff) };
        tls_reader_init(&rr);
        tls_reader_feed(&rr, hmax, 5);
        check_int("6. max body length accepted (needs body)", tls_reader_next(&rr, &rec, &rl), 0);
        uint8_t hover[5] = { 0x17, 0x03, 0x03, ((TLS_RECORD_MAX_BODY + 1) >> 8), ((TLS_RECORD_MAX_BODY + 1) & 0xff) };
        tls_reader_init(&rr);
        tls_reader_feed(&rr, hover, 5);
        check_int("6. over-limit length -> -1", tls_reader_next(&rr, &rec, &rl), -1);

        /* 7. truncated stream: header says 2000, only 1500 arrive -> need-more + pending */
        uint8_t thdr[5] = { 0x17, 0x03, 0x03, (2000 >> 8), (2000 & 0xff) };
        uint8_t body[1500]; memset(body, 0xAB, sizeof body);
        tls_reader_init(&rr);
        tls_reader_feed(&rr, thdr, 5);
        tls_reader_feed(&rr, body, sizeof body);
        check_int("7. truncated record -> need more", tls_reader_next(&rr, &rec, &rl), 0);
        check_int("7. and bytes remain pending (EOF here = truncated)",
                  tls_reader_pending(&rr) == 5 + 1500, 1);
    }

    printf("TLS 1.3 handshake driver (byte stream -> CONNECTED):\n");
    {
        /* Build one authenticated server flight (real chain + real RSA-PSS
         * CertificateVerify), seal it into wire records the way openssl s_server
         * would -- SH plaintext, then EE | Certificate | CertificateVerify |
         * Finished each as its own encrypted handshake record -- and run the
         * driver over it under several adversarial read/write chunkings. */
        uint8_t cad[700]; x509_cert ca;
        x509_parse(cad, unhex(T_CA_CERT, cad), &ca);
        uint8_t leafd[700]; int leaflen = unhex(T_LEAF_CERT, leafd);
        uint8_t certmsg[800]; int cmlen = build_cert_msg(certmsg, leafd, leaflen);
        uint8_t ln[128], ld[128]; int lnlen = unhex(T_LEAF_N, ln), ldlen = unhex(T_LEAF_D, ld);
        uint64_t now2026 = 1767225600ULL;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+21); spriv[i]=(uint8_t)(0xE0+i);
                                crand[i]=(uint8_t)(0xBB+i); srand[i]=(uint8_t)(0xCC+i); }
        uint8_t spub[32], cpub[32]; x25519_base(spub, spriv); x25519_base(cpub, cpriv);

        /* reference ClientHello (deterministic): the driver's own tls_conn_start
         * produces these exact bytes, so the flight built against them matches */
        tls_client ref; tls_client_init(&ref, "example.com", cpriv, crand);
        uint8_t ch[1024]; int chlen = tls_client_start(&ref, ch, sizeof ch);

        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256]; int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);
        uint8_t hello_hash[32], ecdhe[32]; tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss; tls_key_schedule_derive(&kss, ecdhe, hello_hash);

        uint8_t ee[64]; int eelen = build_hs(ee, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, certmsg, cmlen);
        uint8_t th_cert[32]; tls_transcript_hash(&ts, th_cert);
        uint8_t cvmsg[256]; int cvlen = pss_sign_cv(cvmsg, th_cert, ln, lnlen, ld, ldlen);
        tls_transcript_update(&ts, cvmsg, cvlen);
        uint8_t sfk[32], th_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, th_cv);
        tls_finished_verify_data(svd, sfk, th_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);
        tls_transcript_update(&ts, sfin, sfinlen);          /* Transcript(CH..server Finished) */
        uint8_t thash_sf[32], cfk[32];
        tls_transcript_hash(&ts, thash_sf);
        tls_finished_key(cfk, kss.client_hs_traffic);       /* to verify the client's Finished */

        /* seal the flight into the server byte stream */
        tls_record_keys s_tx; epoch_from_secret(&s_tx, kss.server_hs_traffic);
        uint8_t stream[4096]; int sn = 0; uint8_t r[1024]; int rl;
        sn += plaintext_wrap(stream + sn, TLS_CONTENT_HANDSHAKE, sh, shlen);
        rl = tls_record_seal(&s_tx, TLS_CONTENT_HANDSHAKE, ee, eelen, r, sizeof r);
        for (int i=0;i<rl;i++) stream[sn++] = r[i];
        int cert_off = sn;                                  /* Certificate record begins here */
        rl = tls_record_seal(&s_tx, TLS_CONTENT_HANDSHAKE, certmsg, cmlen, r, sizeof r);
        for (int i=0;i<rl;i++) stream[sn++] = r[i];
        int cert_mid = cert_off + rl / 2;                   /* a byte boundary inside the cert */
        rl = tls_record_seal(&s_tx, TLS_CONTENT_HANDSHAKE, cvmsg, cvlen, r, sizeof r);
        for (int i=0;i<rl;i++) stream[sn++] = r[i];
        rl = tls_record_seal(&s_tx, TLS_CONTENT_HANDSHAKE, sfin, sfinlen, r, sizeof r);
        int fin_off = sn;                                   /* Finished record begins here */
        for (int i=0;i<rl;i++) stream[sn++] = r[i];

        static tls_conn dcn; static tls_record_reader drd;  /* big: keep off the stack */
        mockx mx;

        /* scenario 2: the whole flight (5 records) arrives in one read */
        memset(&mx,0,sizeof mx); mx.read_chunk = 0; mx.write_chunk = 0;
        check_int("all-at-once: driver reaches CONNECTED", drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);
        check_int("all-at-once: full milestone trace", milestones_ok(), 1);
        check_int("all-at-once: one read consumed the stream", mx.in_pos, sn);

        /* the captured client output must be ClientHello (plaintext) + an encrypted
         * Finished that verifies server-side -- a real, valid client response */
        check_int("client wrote ClientHello first (plaintext handshake)", (mx.out_len > 5 && mx.out[0] == TLS_CONTENT_HANDSHAKE), 1);
        int r1 = 5 + (((int)mx.out[3] << 8) | mx.out[4]);   /* end of the ClientHello record */
        check_int("client ClientHello matches the reference bytes", (r1 == 5 + chlen && memcmp(mx.out + 5, ch, chlen) == 0), 1);
        check_int("client wrote a second (encrypted) record", (mx.out_len > r1 + 5 && mx.out[r1] == TLS_CONTENT_APPLICATION_DATA), 1);
        {
            tls_record_keys s_rx; epoch_from_secret(&s_rx, kss.client_hs_traffic);
            uint8_t cfin[64]; uint8_t it;
            int n = tls_record_open(&s_rx, mx.out + r1, mx.out_len - r1, cfin, sizeof cfin, &it);
            check_int("server opens the client Finished", (n == 36 && it == TLS_CONTENT_HANDSHAKE), 1);
            check_int("client Finished verifies server-side", tls_check_finished(cfk, thash_sf, cfin + 4), 0);
        }
        /* keep this clean capture as the reference for the partial-write scenario */
        uint8_t ref_out[2048]; int ref_outlen = mx.out_len;
        memcpy(ref_out, mx.out, (size_t)mx.out_len);

        /* scenario 1: every byte delivered separately (read 1, write 1) */
        memset(&mx,0,sizeof mx); mx.read_chunk = 1; mx.write_chunk = 1;
        check_int("byte-by-byte: driver reaches CONNECTED", drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);
        check_int("byte-by-byte: full milestone trace", milestones_ok(), 1);

        /* scenario 3: a read boundary lands inside the Certificate record (first
         * read = SH+EE+half the cert; the reader reassembles across the split) */
        memset(&mx,0,sizeof mx); mx.first_read = cert_mid; mx.read_chunk = 0; mx.write_chunk = 0;
        check_int("split mid-Certificate: driver reaches CONNECTED", drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);
        check_int("split mid-Certificate: full milestone trace", milestones_ok(), 1);

        /* scenario 4: send() only ever accepts 1 byte -> send_all must loop, yet
         * the captured output is byte-identical to the clean run (nothing lost or
         * reordered by the partial writes) */
        memset(&mx,0,sizeof mx); mx.read_chunk = 0; mx.write_chunk = 1;
        check_int("partial writes: driver reaches CONNECTED", drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);
        check_int("partial writes: output byte-identical despite 1-byte send()",
                  (mx.out_len == ref_outlen && memcmp(mx.out, ref_out, (size_t)ref_outlen) == 0), 1);

        /* negative: a flight truncated before the Finished -> EOF, never a silent
         * "connected". The driver must report EOF before CONNECTED as fatal. */
        memset(&mx,0,sizeof mx); mx.read_chunk = 0; mx.write_chunk = 0;
        check_int("truncated flight (no Finished) -> EOF, not CONNECTED",
                  drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,fin_off,&mx), TLS_DRIVE_EOF);

        /* ---- application data over the live (driver-established) epoch ---- */
        /* Re-drive cleanly so dcn is CONNECTED, then exchange app data with the
         * server mirror's application keys. Proves the app traffic secrets match,
         * per-epoch sequence numbers advance both ways, nonce derivation holds on
         * app data, and NewSessionTickets are tolerated. */
        memset(&mx,0,sizeof mx); mx.read_chunk = 0; mx.write_chunk = 0;
        check_int("appdata: re-drive reaches CONNECTED",
                  drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);

        uint8_t s_cap[32], s_sap[32];
        tls_derive_secret(s_cap, kss.master_secret, "c ap traffic", thash_sf);
        tls_derive_secret(s_sap, kss.master_secret, "s ap traffic", thash_sf);
        tls_record_keys s_tx_ap, s_rx_ap;
        epoch_from_secret(&s_tx_ap, s_sap);     /* server writes app data       */
        epoch_from_secret(&s_rx_ap, s_cap);     /* server reads client app data */

        /* client -> server, two records: the server must decrypt both, and the
         * second proves the client's app tx sequence number advanced (seq 0,1) */
        uint8_t qrec[256], sp[64], it; size_t ol;
        const char *m1 = "PING\n"; char m1hex[16]; tohex((const uint8_t*)m1, 5, m1hex);
        int q1 = tls_conn_send_app(&dcn, (const uint8_t*)m1, 5, qrec, sizeof qrec);
        int o1 = tls_record_open(&s_rx_ap, qrec, q1, sp, sizeof sp, &it);
        check("server decrypts client app record #0 (PING)", sp, o1, m1hex);
        const char *m2 = "PING2"; char m2hex[16]; tohex((const uint8_t*)m2, 5, m2hex);
        int q2 = tls_conn_send_app(&dcn, (const uint8_t*)m2, 5, qrec, sizeof qrec);
        int o2 = tls_record_open(&s_rx_ap, qrec, q2, sp, sizeof sp, &it);
        check("server decrypts client app record #1 (seq advanced)", sp, o2, m2hex);

        /* server -> client, two records: the client must decrypt both (rx seq 0,1) */
        uint8_t arec[256], cp[64]; size_t cl2;
        const char *r1m = "PONG\n"; char r1hex[16]; tohex((const uint8_t*)r1m, 5, r1hex);
        int a1 = tls_record_seal(&s_tx_ap, TLS_CONTENT_APPLICATION_DATA, (const uint8_t*)r1m, 5, arec, sizeof arec);
        check_int("client recv server app record #0 -> OK",
                  tls_conn_recv_app(&dcn, arec, a1, cp, sizeof cp, &cl2), TLS_CONN_OK);
        check("client decrypts server app record #0 (PONG)", cp, (int)cl2, r1hex);
        const char *r2m = "PONG2"; char r2hex[16]; tohex((const uint8_t*)r2m, 5, r2hex);
        int a2 = tls_record_seal(&s_tx_ap, TLS_CONTENT_APPLICATION_DATA, (const uint8_t*)r2m, 5, arec, sizeof arec);
        check_int("client recv server app record #1 -> OK (rx seq advanced)",
                  tls_conn_recv_app(&dcn, arec, a2, cp, sizeof cp, &cl2), TLS_CONN_OK);
        check("client decrypts server app record #1 (PONG2)", cp, (int)cl2, r2hex);

        /* a NewSessionTicket (a handshake message inside an app-data record) is
         * accepted and ignored -- the program must not choke on OpenSSL's ticket */
        uint8_t nst[16]; int nstl = build_hs(nst, 4 /* new_session_ticket */, (const uint8_t*)"\x00\x00\x00\x00", 4);
        uint8_t nrec[64]; int nl = tls_record_seal(&s_tx_ap, TLS_CONTENT_HANDSHAKE, nst, nstl, nrec, sizeof nrec);
        size_t nout = 99;
        check_int("client accepts NewSessionTicket -> OK",
                  tls_conn_recv_app(&dcn, nrec, nl, cp, sizeof cp, &nout), TLS_CONN_OK);
        check_int("NewSessionTicket yields no app data", (int)nout, 0);

        /* a tampered app record is rejected (AEAD), connection-fatal at the app layer */
        int a3 = tls_record_seal(&s_tx_ap, TLS_CONTENT_APPLICATION_DATA, (const uint8_t*)"x", 1, arec, sizeof arec);
        arec[7] ^= 1;
        check_int("tampered app record -> ERR_RECORD",
                  tls_conn_recv_app(&dcn, arec, a3, cp, sizeof cp, &cl2), TLS_CONN_ERR_RECORD);
    }

    printf("TLS 1.3 oversized certificate chain (multi-cert, many records):\n");
    {
        /* A realistic two-cert chain (leaf + CA), several hundred bytes, sealed
         * into MANY tiny records so the Certificate message spans ~20 records and
         * the read boundaries are misaligned to record boundaries -- the worst
         * case for the conn's reassembly and the reader's framing together. */
        uint8_t cad[700]; x509_cert ca;
        int calen = unhex(T_CA_CERT, cad);
        x509_parse(cad, calen, &ca);
        uint8_t leafd[700]; int leaflen = unhex(T_LEAF_CERT, leafd);
        const uint8_t *ders[2] = { leafd, cad };
        const int      lens[2] = { leaflen, calen };
        uint8_t certmsg[1600]; int cmlen = build_cert_msg_n(certmsg, ders, lens, 2);
        uint8_t ln[128], ld[128]; int lnlen = unhex(T_LEAF_N, ln), ldlen = unhex(T_LEAF_D, ld);
        uint64_t now2026 = 1767225600ULL;

        uint8_t cpriv[32], spriv[32], crand[32], srand[32];
        for (int i=0;i<32;i++){ cpriv[i]=(uint8_t)(i+31); spriv[i]=(uint8_t)(0x10+i);
                                crand[i]=(uint8_t)(0xC1+i); srand[i]=(uint8_t)(0xD2+i); }
        uint8_t spub[32], cpub[32]; x25519_base(spub, spriv); x25519_base(cpub, cpriv);

        tls_client ref; tls_client_init(&ref, "example.com", cpriv, crand);
        uint8_t ch[1024]; int chlen = tls_client_start(&ref, ch, sizeof ch);

        tls_transcript ts; tls_transcript_init(&ts);
        tls_transcript_update(&ts, ch, chlen);
        uint8_t sh[256]; int shlen = build_server_hello(sh, srand, TLS_CIPHER_CHACHA20_POLY1305_SHA256, spub);
        tls_transcript_update(&ts, sh, shlen);
        uint8_t hello_hash[32], ecdhe[32]; tls_transcript_hash(&ts, hello_hash);
        x25519(ecdhe, spriv, cpub);
        tls_key_schedule kss; tls_key_schedule_derive(&kss, ecdhe, hello_hash);

        uint8_t ee[64]; int eelen = build_hs(ee, TLS_HS_ENCRYPTED_EXTENSIONS, (const uint8_t*)"\x00\x00", 2);
        tls_transcript_update(&ts, ee, eelen);
        tls_transcript_update(&ts, certmsg, cmlen);
        uint8_t th_cert[32]; tls_transcript_hash(&ts, th_cert);
        uint8_t cvmsg[256]; int cvlen = pss_sign_cv(cvmsg, th_cert, ln, lnlen, ld, ldlen);
        tls_transcript_update(&ts, cvmsg, cvlen);
        uint8_t sfk[32], th_cv[32], svd[32], sfin[64];
        tls_finished_key(sfk, kss.server_hs_traffic);
        tls_transcript_hash(&ts, th_cv);
        tls_finished_verify_data(svd, sfk, th_cv);
        int sfinlen = build_hs(sfin, TLS_HS_FINISHED, svd, 32);

        /* coalesce the four messages, then chop into 48-byte record bodies */
        static uint8_t flight[2048]; int fl = 0;
        for (int i=0;i<eelen;i++)   flight[fl++] = ee[i];
        for (int i=0;i<cmlen;i++)   flight[fl++] = certmsg[i];
        for (int i=0;i<cvlen;i++)   flight[fl++] = cvmsg[i];
        for (int i=0;i<sfinlen;i++) flight[fl++] = sfin[i];

        tls_record_keys s_tx; epoch_from_secret(&s_tx, kss.server_hs_traffic);
        static uint8_t stream[8192]; int sn = 0;
        sn += plaintext_wrap(stream + sn, TLS_CONTENT_HANDSHAKE, sh, shlen);
        int nrecs = 0;
        for (int off = 0; off < fl; off += 48) {
            int chunk = (fl - off < 48) ? fl - off : 48;
            uint8_t rec[128];
            int rl = tls_record_seal(&s_tx, TLS_CONTENT_HANDSHAKE, flight + off, chunk, rec, sizeof rec);
            for (int i=0;i<rl;i++) stream[sn++] = rec[i];
            nrecs++;
        }
        check_int("flight chopped into many records (>15)", nrecs > 15, 1);

        static tls_conn dcn; static tls_record_reader drd; mockx mx;
        memset(&mx,0,sizeof mx); mx.read_chunk = 40;   /* reads misaligned to records */
        check_int("oversized chain across many records -> CONNECTED",
                  drive_once(&dcn,&drd,cpriv,crand,&ca,now2026,stream,sn,&mx), TLS_DRIVE_OK);
        check_int("oversized chain: full milestone trace", milestones_ok(), 1);
        check_int("parsed both chain certs (leaf + CA)", (int)dcn.fsm.certs.count, 2);

        /* buffer-safety: a Certificate message declaring a length beyond the
         * reassembly buffer must be rejected cleanly (ERR_CAPACITY), never
         * overflowed. Get into the handshake epoch, then feed one record whose
         * plaintext is a Certificate header claiming 0x010000 (> hs_buf) bytes. */
        static tls_conn ocn; static tls_record_reader ord;
        tls_conn_init(&ocn, "example.com", cpriv, crand);
        tls_client_set_trust(&ocn.fsm, &ca, 1, now2026);
        tls_reader_init(&ord);
        uint8_t crec[1100]; tls_conn_start(&ocn, crec, sizeof crec);
        uint8_t shrec[300]; int shrl = plaintext_wrap(shrec, TLS_CONTENT_HANDSHAKE, sh, shlen);
        uint8_t o2[64]; size_t ol2;
        tls_conn_recv_record(&ocn, shrec, shrl, o2, sizeof o2, &ol2);   /* -> HANDSHAKE epoch */
        tls_record_keys s_tx2; epoch_from_secret(&s_tx2, kss.server_hs_traffic);
        uint8_t huge_hdr[4] = { TLS_HS_CERTIFICATE, 0x01, 0x00, 0x00 }; /* len = 65536 > 32768 */
        uint8_t hrec[64]; int hrl = tls_record_seal(&s_tx2, TLS_CONTENT_HANDSHAKE, huge_hdr, 4, hrec, sizeof hrec);
        uint8_t ho[64]; size_t hol;
        check_int("over-buffer Certificate length -> ERR_CAPACITY",
                  tls_conn_recv_record(&ocn, hrec, hrl, ho, sizeof ho, &hol), TLS_CONN_ERR_CAPACITY);
        check_int("over-buffer Certificate did not reach CONNECTED", tls_conn_connected(&ocn), 0);
    }

    printf(failures ? "\nTLS TEST: %d FAILURE(S)\n" : "\nTLS TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
