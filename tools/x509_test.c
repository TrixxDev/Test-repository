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

        /* dispatcher: an ECDSA-signed cert is reported UNSUPPORTED, not failed */
        static const uint8_t oid_ecdsa[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };
        x509_cert fake = cert;
        fake.sig_oid.p = oid_ecdsa; fake.sig_oid.len = sizeof oid_ecdsa;
        check_ok("ECDSA signature algorithm -> UNSUPPORTED",
                 x509_verify_signature(&fake, cert.spki_key.p, cert.spki_key.len) == X509_VERIFY_UNSUPPORTED);
    }

    printf(failures ? "\nX509 TEST: %d FAILURE(S)\n" : "\nX509 TEST: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
