/* Host-side X.509 / PKI tests. v1 covers the ASN.1 DER reader (x509/asn1.c):
 * synthetic TLVs for every accept/reject path, plus a structural walk of the
 * real RFC 8448 server certificate (a genuine DER blob). Build/run:
 * `make x509-test`. No QEMU, no networking. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "asn1.h"
#include "x509.h"
#include "verify_cert.h"

/* The 432-byte DER certificate from RFC 8448 §3 (extracted verbatim). */
#define RFC_DER_CERT "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1"

/* A synthetic minimal certificate carrying a SubjectAltName with two dNSName
 * entries (RFC 8448's cert has none). Built by tools (correct DER lengths). */
#define SAN_CERT "3081ca3081b1a003020102020101300d06092a864886f70d01010b050030123110300e0603550403130754657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d301f300d06092a864886f70d0101010500030e00300b020400c0ffee0203010001a32b302930270603551d110420301e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d300d06092a864886f70d01010b0500030500deadbeef"

/* A real ECDSA P-256 / ecdsa-with-SHA256 self-signed certificate, CN/SAN =
 * aurora-ec-test (test/tls/ec_cert.pem). Generated with:
 *   openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem
 *   openssl req -x509 -new -key ec_key.pem -sha256 -days 3650 \
 *       -subj "/CN=aurora-ec-test" -addext "subjectAltName=DNS:aurora-ec-test" \
 *       -out ec_cert.pem
 * This is the analogue of RFC_DER_CERT for the ECDSA verification path. */
#define EC_CERT "308201a230820148a003020102021475f0594af486a3924c0107c26e17f37afff12fb7300a06082a8648ce3d04030230193117301506035504030c0e6175726f72612d65632d74657374301e170d3236303632343037353834355a170d3336303632313037353834355a30193117301506035504030c0e6175726f72612d65632d746573743059301306072a8648ce3d020106082a8648ce3d0301070342000495982cd8b24b904afc1a61e9ebb41c858b3f7ebe2f237133a0e28e23f67af4501d856285231af5fe01da4df2da8757b4c037be0bce75c1e7ec4f6f6ed76d1a31a36e306c301d0603551d0e04160414504dc74f919284b4687854efb57f3c251615bea4301f0603551d23041830168014504dc74f919284b4687854efb57f3c251615bea4300f0603551d130101ff040530030101ff30190603551d1104123010820e6175726f72612d65632d74657374300a06082a8648ce3d04030203480030450221009a1c56dbedf726b01bcfbb03b67fadc567c88c643a50aa5670fac6d554a8576c02201790e03885d6bdb1eb6f01a266a75bbff57c62d740c20842971d8c61d962d460"

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

/* parse a single TLV from a byte literal; return the asn1_next result */
static int parse1(const uint8_t *buf, size_t len, asn1_tlv *t)
{
    asn1_cursor c; asn1_cursor_init(&c, buf, len);
    return asn1_next(&c, t);
}

int main(void)
{
    printf("ASN.1 DER reader — TLV basics:\n");
    {
        asn1_tlv t;
        uint8_t i5[]  = { 0x02, 0x01, 0x05 };               /* INTEGER 5 */
        check_ok("INTEGER parses (tag/len)", parse1(i5, sizeof i5, &t) == 0 && t.tag == ASN1_INTEGER && t.len == 1);
        uint64_t v = 0;
        check_ok("INTEGER value == 5", asn1_get_uint(&t, &v) == 0 && v == 5);

        uint8_t os[] = { 0x04, 0x03, 0xaa, 0xbb, 0xcc };    /* OCTET STRING */
        check_ok("OCTET STRING len == 3", parse1(os, sizeof os, &t) == 0 && t.tag == ASN1_OCTET_STRING && t.len == 3);

        /* long-form length: 0x81 0x80 => 128 content octets */
        uint8_t lf[131]; lf[0] = 0x04; lf[1] = 0x81; lf[2] = 0x80;
        for (int i = 0; i < 128; i++) lf[3 + i] = (uint8_t)i;
        check_ok("long-form length == 128", parse1(lf, sizeof lf, &t) == 0 && t.len == 128 && t.value[127] == 127);

        /* SEQUENCE { INTEGER 1, INTEGER 2 } — open and iterate */
        uint8_t seq[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        asn1_cursor c; asn1_cursor_init(&c, seq, sizeof seq);
        asn1_cursor in;
        check_ok("SEQUENCE opens", asn1_open(&c, ASN1_SEQUENCE, &in) == 0);
        asn1_tlv a, b; uint64_t va = 0, vb = 0;
        int ok = asn1_next(&in, &a) == 0 && asn1_get_uint(&a, &va) == 0
              && asn1_next(&in, &b) == 0 && asn1_get_uint(&b, &vb) == 0;
        check_ok("two INTEGERs 1,2 in order", ok && va == 1 && vb == 2);
        check_ok("inner cursor fully consumed", asn1_cursor_empty(&in));
        check_ok("outer cursor fully consumed", asn1_cursor_empty(&c));

        uint8_t tag = 0;
        asn1_cursor_init(&c, seq, sizeof seq);
        check_ok("peek does not consume", asn1_peek_tag(&c, &tag) == 0 && tag == ASN1_SEQUENCE && c.p == seq);
    }

    printf("ASN.1 DER reader — rejects malformed input:\n");
    {
        asn1_tlv t;
        check_ok("empty buffer -> -1", parse1((const uint8_t*)"", 0, &t) == -1);
        uint8_t no_len[]  = { 0x02 };
        check_ok("missing length octet -> -1", parse1(no_len, sizeof no_len, &t) == -1);
        uint8_t over[]    = { 0x04, 0x05, 0xaa, 0xbb };     /* claims 5, has 2 */
        check_ok("length exceeds buffer -> -1", parse1(over, sizeof over, &t) == -1);
        uint8_t indef[]   = { 0x30, 0x80, 0x00, 0x00 };     /* indefinite length */
        check_ok("indefinite length -> -1", parse1(indef, sizeof indef, &t) == -1);
        uint8_t nonmin[]  = { 0x02, 0x81, 0x01, 0x05 };     /* long form for len 1 */
        check_ok("non-minimal long form -> -1", parse1(nonmin, sizeof nonmin, &t) == -1);
        uint8_t leadzero[] = { 0x02, 0x82, 0x00, 0x80 };    /* leading zero length octet */
        check_ok("leading-zero length octet -> -1", parse1(leadzero, sizeof leadzero, &t) == -1);
        uint8_t hightag[] = { 0x1f, 0x20, 0x01, 0x00 };     /* high-tag-number form */
        check_ok("high-tag-number form -> -1", parse1(hightag, sizeof hightag, &t) == -1);
        uint8_t lenoflen[] = { 0x04, 0x85, 0x01,0x02,0x03,0x04,0x05 }; /* 5 length octets */
        check_ok("oversized length-of-length -> -1", parse1(lenoflen, sizeof lenoflen, &t) == -1);

        uint8_t neg[] = { 0x02, 0x01, 0xff };               /* INTEGER, high bit set */
        check_ok("INTEGER parses but get_uint rejects negative", parse1(neg, sizeof neg, &t) == 0 && asn1_get_uint(&t, (uint64_t[]){0}) == -1);
        uint8_t nmi[] = { 0x02, 0x02, 0x00, 0x05 };         /* non-minimal INTEGER */
        check_ok("non-minimal INTEGER -> get_uint -1", parse1(nmi, sizeof nmi, &t) == 0 && asn1_get_uint(&t, (uint64_t[]){0}) == -1);

        /* expect() restores the cursor on a tag mismatch */
        asn1_cursor c; asn1_cursor_init(&c, neg, sizeof neg);
        check_ok("expect(wrong tag) -> -1 and cursor unchanged",
                 asn1_expect(&c, ASN1_SEQUENCE, &t) == -1 && c.p == neg);
    }

    printf("ASN.1 DER reader — RFC 8448 server certificate (real DER):\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        check_ok("DER blob is 432 bytes", derlen == 432);

        /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
        asn1_cursor c; asn1_cursor_init(&c, der, derlen);
        asn1_cursor cert;
        check_ok("Certificate SEQUENCE opens", asn1_open(&c, ASN1_SEQUENCE, &cert) == 0);
        check_ok("nothing trails the outer SEQUENCE", asn1_cursor_empty(&c));

        asn1_tlv tbs, sigalg, sig;
        int top = asn1_expect(&cert, ASN1_SEQUENCE, &tbs) == 0      /* tbsCertificate */
               && asn1_expect(&cert, ASN1_SEQUENCE, &sigalg) == 0   /* signatureAlgorithm */
               && asn1_expect(&cert, ASN1_BIT_STRING, &sig) == 0;   /* signatureValue */
        check_ok("three top-level fields parse", top);
        check_ok("Certificate fully consumed", asn1_cursor_empty(&cert));
        check_ok("tbsCertificate length == 277", tbs.len == 277);
        check_ok("signatureValue is a BIT STRING", sig.tag == ASN1_BIT_STRING);

        /* descend into tbsCertificate */
        asn1_cursor tc; asn1_cursor_init(&tc, tbs.value, tbs.len);

        /* [0] EXPLICIT version => INTEGER 2 (v3) */
        asn1_cursor ver;
        uint8_t vt = 0;
        check_ok("version is context [0] (0xA0)", asn1_peek_tag(&tc, &vt) == 0 && vt == (ASN1_CONTEXT|ASN1_CONSTRUCTED|0));
        asn1_tlv vint; uint64_t version = 99;
        int vok = asn1_open(&tc, ASN1_CONTEXT|ASN1_CONSTRUCTED|0, &ver) == 0
               && asn1_next(&ver, &vint) == 0 && asn1_get_uint(&vint, &version) == 0;
        check_ok("version == 2 (v3)", vok && version == 2);

        /* serialNumber INTEGER == 2 */
        asn1_tlv serial; uint64_t sn = 99;
        check_ok("serialNumber == 2", asn1_expect(&tc, ASN1_INTEGER, &serial) == 0
                 && asn1_get_uint(&serial, &sn) == 0 && sn == 2);

        /* signature AlgorithmIdentifier => OID sha256WithRSAEncryption */
        static const uint8_t oid_sha256rsa[] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
        asn1_cursor alg; asn1_tlv algoid;
        int aok = asn1_open(&tc, ASN1_SEQUENCE, &alg) == 0 && asn1_next(&alg, &algoid) == 0;
        check_ok("signature algorithm == sha256WithRSAEncryption",
                 aok && asn1_oid_equals(&algoid, oid_sha256rsa, sizeof oid_sha256rsa));

        /* issuer SEQUENCE (skip), then validity { UTCTime, UTCTime } */
        asn1_tlv issuer;
        check_ok("issuer is a SEQUENCE", asn1_expect(&tc, ASN1_SEQUENCE, &issuer) == 0);
        asn1_cursor val; asn1_tlv nb, na;
        int vlok = asn1_open(&tc, ASN1_SEQUENCE, &val) == 0
                && asn1_expect(&val, ASN1_UTCTIME, &nb) == 0
                && asn1_expect(&val, ASN1_UTCTIME, &na) == 0;
        check_ok("validity has two UTCTime fields", vlok);
        check_ok("notBefore == 160730012359Z",
                 vlok && nb.len == 13 && memcmp(nb.value, "160730012359Z", 13) == 0);
    }

    printf("X.509 parser — RFC 8448 server certificate:\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("version == 2 (v3)", cert.version == 2);
        check_ok("serialNumber == 2", cert.serial.len == 1 && cert.serial.p[0] == 2);
        check_ok("issuer CN == \"rsa\"", strcmp(cert.issuer_cn, "rsa") == 0);
        check_ok("subject CN == \"rsa\"", strcmp(cert.subject_cn, "rsa") == 0);
        check_ok("public key algorithm == RSA", cert.pubkey_algo == X509_PK_RSA);
        check_ok("SPKI length == 162 (full element)", cert.spki.len == 162);
        check_ok("TBSCertificate length == 281 (full element)", cert.tbs.len == 281);
        check_ok("signatureValue length == 128 (RSA-1024)", cert.signature.len == 128);
        static const uint8_t oid_sha256rsa[] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
        check_ok("signature OID == sha256WithRSAEncryption",
                 x509_slice_eq(&cert.sig_oid, oid_sha256rsa, sizeof oid_sha256rsa));
        check_ok("notBefore == 2016-07-30 01:23:59Z (1469841839)", cert.not_before == 1469841839ULL);
        check_ok("notAfter  == 2026-07-30 01:23:59Z (1785374639)", cert.not_after == 1785374639ULL);
        check_ok("notBefore < notAfter", cert.not_before < cert.not_after);
        check_ok("no SAN entries", cert.san_count == 0);
    }

    printf("X.509 parser — synthetic certificate with SubjectAltName:\n");
    {
        uint8_t der[512];
        int derlen = unhex(SAN_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("subject CN == \"example.com\"", strcmp(cert.subject_cn, "example.com") == 0);
        check_ok("issuer CN == \"Test CA\"", strcmp(cert.issuer_cn, "Test CA") == 0);
        check_ok("public key algorithm == RSA", cert.pubkey_algo == X509_PK_RSA);
        check_ok("san_count == 2", cert.san_count == 2);
        check_ok("SAN[0] == example.com",     cert.san_count > 0 && strcmp(cert.san_dns[0], "example.com") == 0);
        check_ok("SAN[1] == www.example.com", cert.san_count > 1 && strcmp(cert.san_dns[1], "www.example.com") == 0);
        check_ok("notBefore == 2024-01-01Z (1704067200)", cert.not_before == 1704067200ULL);
        check_ok("notAfter  == 2034-01-01Z (2019686400)", cert.not_after == 2019686400ULL);
    }

    printf("X.509 signature — RFC 8448 self-signed certificate (end-to-end PKI):\n");
    {
        uint8_t der[512];
        int derlen = unhex(RFC_DER_CERT, der);
        x509_cert cert;
        check_ok("certificate parses", x509_parse(der, derlen, &cert) == 0);

        /* self-signed: the issuer key is the cert's own SubjectPublicKey */
        int rc = x509_verify_signature(&cert, cert.spki_key.p, cert.spki_key.len);
        check_ok("RSA/SHA-256 signature verifies over TBSCertificate", rc == X509_VERIFY_OK);

        /* flip one byte inside the TBSCertificate -> signature must fail */
        uint8_t der2[512]; memcpy(der2, der, derlen);
        x509_cert cert2;
        check_ok("tampered cert re-parses", x509_parse(der2, derlen, &cert2) == 0);
        /* cert2.tbs points into der2; corrupt its first content byte */
        der2[(cert2.tbs.p - der2) + 8] ^= 1;
        check_ok("tampered TBSCertificate -> BAD_SIGNATURE",
                 x509_verify_signature(&cert2, cert2.spki_key.p, cert2.spki_key.len) == X509_VERIFY_BAD_SIGNATURE);

        /* dispatcher: a genuinely unimplemented algorithm (ecdsa-with-SHA384) is
         * reported UNSUPPORTED, not failed. ecdsa-with-SHA256 is now supported and
         * is exercised against a real ECDSA cert below. */
        static const uint8_t oid_ecdsa384[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03 };
        x509_cert fake = cert;
        fake.sig_oid.p = oid_ecdsa384; fake.sig_oid.len = sizeof oid_ecdsa384;
        check_ok("unimplemented signature algorithm -> UNSUPPORTED",
                 x509_verify_signature(&fake, cert.spki_key.p, cert.spki_key.len) == X509_VERIFY_UNSUPPORTED);
    }

    printf("X.509 signature — ECDSA P-256 / SHA-256 self-signed certificate (13.x.4):\n");
    {
        uint8_t der[512];
        int derlen = unhex(EC_CERT, der);
        x509_cert cert;
        check_ok("ECDSA certificate parses", x509_parse(der, derlen, &cert) == 0);
        check_ok("public key algorithm == EC (prime256v1 named curve checked)",
                 cert.pubkey_algo == X509_PK_EC);
        check_ok("subject CN == \"aurora-ec-test\"", strcmp(cert.subject_cn, "aurora-ec-test") == 0);
        check_ok("SAN[0] == aurora-ec-test",
                 cert.san_count == 1 && strcmp(cert.san_dns[0], "aurora-ec-test") == 0);
        static const uint8_t oid_ecdsa256[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };
        check_ok("signature OID == ecdsa-with-SHA256",
                 x509_slice_eq(&cert.sig_oid, oid_ecdsa256, sizeof oid_ecdsa256));
        check_ok("EC subjectPublicKey is 65-byte uncompressed point",
                 cert.spki_key.len == 65 && cert.spki_key.p[0] == 0x04);

        /* KAT #1 — positive: the self-signed ECDSA signature verifies over its
         * own TBSCertificate (issuer key = the cert's own SubjectPublicKey). */
        int rc = x509_verify_signature(&cert, cert.spki_key.p, cert.spki_key.len);
        check_ok("KAT#1 ECDSA/SHA-256 signature verifies (cert -> PASS)", rc == X509_VERIFY_OK);
        x509_cert roots[] = { cert };
        check_ok("KAT#1 trusts itself as a root via x509_verify_chain",
                 x509_verify_chain(&cert, roots, 1) == X509_VERIFY_OK);

        /* KAT #2 — tamper TBSCertificate: flip one content byte (the version
         * value); the cert still parses but SHA-256(tbs) changes, so the
         * signature must no longer verify. Proves the signature is actually
         * checked against the body, not merely that the structure is well-formed. */
        uint8_t der2[512]; memcpy(der2, der, derlen);
        x509_cert cert2;
        check_ok("tampered-TBS cert re-parses", x509_parse(der2, derlen, &cert2) == 0);
        der2[(cert2.tbs.p - der2) + 8] ^= 1;
        check_ok("KAT#2 tampered TBSCertificate -> BAD_SIGNATURE (cert -> FAIL)",
                 x509_verify_signature(&cert2, cert2.spki_key.p, cert2.spki_key.len)
                     == X509_VERIFY_BAD_SIGNATURE);

        /* KAT #3 — tamper the signature: flip the last byte of the ECDSA-Sig-Value
         * (changes s). The DER still parses strictly but the verification
         * equation fails. Exercises the dispatcher + DER signature path. */
        uint8_t der3[512]; memcpy(der3, der, derlen);
        x509_cert cert3;
        check_ok("tampered-signature cert re-parses", x509_parse(der3, derlen, &cert3) == 0);
        der3[(cert3.signature.p - der3) + cert3.signature.len - 1] ^= 1;
        check_ok("KAT#3 tampered signature -> BAD_SIGNATURE (cert -> FAIL)",
                 x509_verify_signature(&cert3, cert3.spki_key.p, cert3.spki_key.len)
                     == X509_VERIFY_BAD_SIGNATURE);
    }

    printf("X.509 trust chain / validity / hostname (synthetic CA + leaf):\n");
    {
        /* CA is self-signed; LEAF is signed by CA, SAN = example.com,
         * www.example.com, *.test.example (from tools/mkchain). */
        #define CA_CERT   "308201a63082010fa003020102020101300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3019311730150603550403130e4175726f7261205465737420434130819f300d06092a864886f70d010101050003818d0030818902818100914dc084000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007732cf66ae551d9f99d4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054abb024451f79ca150203010001300d06092a864886f70d01010b0500038181005aa1a47ee6e84e6bbe29bcb16207087ecfccdbc66214a6c372379ba64d43212d6a496094f564ffe12686ec80517c213d7cc7a295d5efe29917527f36f29599d87031603b8f880864c21fb0fc6723f122230faa66ad05ef17189079508995c42f7aad0850a3844a157ba21a6d0952a4a294bd418a56219eecd1a3430b0fe7323f"
        #define LEAF_CERT "308201e030820149a003020102020102300d06092a864886f70d01010b05003019311730150603550403130e4175726f72612054657374204341301e170d3234303130313030303030305a170d3334303130313030303030305a3016311430120603550403130b6578616d706c652e636f6d30819f300d06092a864886f70d010101050003818d00308189028181008e67a321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007600e22250a7f8ade8900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282c15e8195233abef0203010001a33b303930370603551d110430302e820b6578616d706c652e636f6d820f7777772e6578616d706c652e636f6d820e2a2e746573742e6578616d706c65300d06092a864886f70d01010b050003818100480244df1797489d5f5dd3e84f7f0cbdc9a6f573f22ea7825feccf7a3c13f500e04119491314baa8853e90f5a449d398b8e34e3bf75df7f436d79382d32734978e44870f65c47064c95843197cd8e44b36b6cd6f69753bb33401e9d90a3256965d0a46d199586cf7c6b836a443460995663c4501034f40dd46816071e9d8f951"

        uint8_t cad[512], leafd[512], rfcd[512];
        x509_cert ca, leaf, rfc;
        check_ok("CA parses",   x509_parse(cad,   unhex(CA_CERT, cad),    &ca)   == 0);
        check_ok("leaf parses", x509_parse(leafd, unhex(LEAF_CERT, leafd), &leaf) == 0);
        x509_parse(rfcd, unhex(RFC_DER_CERT, rfcd), &rfc);

        /* 12.4a — trust chain */
        x509_cert roots_good[] = { ca };
        check_ok("leaf trusted by CA root", x509_verify_chain(&leaf, roots_good, 1) == X509_VERIFY_OK);
        x509_cert roots_bad[] = { rfc };       /* an unrelated self-signed root */
        check_ok("leaf NOT trusted by unrelated root",
                 x509_verify_chain(&leaf, roots_bad, 1) == X509_VERIFY_UNTRUSTED);
        check_ok("CA verifies itself (self-signed)", x509_verify_chain(&ca, roots_good, 1) == X509_VERIFY_OK);

        /* 12.4b — validity window (cert valid 2024-01-01 .. 2034-01-01) */
        check_ok("valid in 2026",     x509_check_validity(&leaf, 1767225600ULL) == X509_VALID_OK);
        check_ok("not yet valid 2023", x509_check_validity(&leaf, 1700000000ULL) == X509_VALID_NOT_YET);
        check_ok("expired 2035",      x509_check_validity(&leaf, 2050000000ULL) == X509_VALID_EXPIRED);

        /* 12.4c — hostname (SAN dNSName, CN ignored, one-level wildcard) */
        check_ok("exact: example.com",          x509_check_hostname(&leaf, "example.com") == 0);
        check_ok("exact: www.example.com",      x509_check_hostname(&leaf, "www.example.com") == 0);
        check_ok("case-insensitive: WWW.Example.Com", x509_check_hostname(&leaf, "WWW.Example.Com") == 0);
        check_ok("wildcard: foo.test.example",  x509_check_hostname(&leaf, "foo.test.example") == 0);
        check_ok("wildcard rejects two labels: a.b.test.example",
                 x509_check_hostname(&leaf, "a.b.test.example") == -1);
        check_ok("wildcard rejects bare: test.example",
                 x509_check_hostname(&leaf, "test.example") == -1);
        check_ok("no match: evil.com",          x509_check_hostname(&leaf, "evil.com") == -1);
        check_ok("CN is not used for matching",  x509_check_hostname(&rfc, "rsa") == -1);
    }

    printf(failures ? "\nX509 TEST: %d FAILURE(S)\n" : "\nX509 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
