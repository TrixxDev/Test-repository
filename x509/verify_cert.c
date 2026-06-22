/* X.509 signature verification — see verify_cert.h. */
#include "verify_cert.h"
#include "asn1.h"
#include "sha256.h"
#include "rsa.h"

/* signatureAlgorithm OIDs (raw DER contents) */
static const uint8_t OID_SHA256_RSA[]   = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_ECDSA_SHA256[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };

/* DER DigestInfo prefix for id-sha256 (algorithm + the 32-byte OCTET STRING tag).
 * The 32-byte digest is appended to form the full DigestInfo. */
static const uint8_t SHA256_DIGESTINFO_PREFIX[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};

static void copy(uint8_t *d, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }

/* RSASSA-PKCS1-v1.5 with SHA-256 over the TBSCertificate. */
static int verify_rsa_sha256(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    /* DigestInfo = prefix || SHA-256(TBSCertificate) */
    uint8_t di[sizeof SHA256_DIGESTINFO_PREFIX + 32];
    copy(di, SHA256_DIGESTINFO_PREFIX, sizeof SHA256_DIGESTINFO_PREFIX);
    sha256(cert->tbs.p, cert->tbs.len, di + sizeof SHA256_DIGESTINFO_PREFIX);

    /* issuer public key: RSAPublicKey ::= SEQUENCE { modulus, publicExponent } */
    asn1_cursor c, rsa;
    asn1_cursor_init(&c, ik, iklen);
    if (asn1_open(&c, ASN1_SEQUENCE, &rsa) != 0) return X509_VERIFY_MALFORMED;
    asn1_tlv mod, exp;
    if (asn1_expect(&rsa, ASN1_INTEGER, &mod) != 0) return X509_VERIFY_MALFORMED;
    if (asn1_expect(&rsa, ASN1_INTEGER, &exp) != 0) return X509_VERIFY_MALFORMED;

    /* drop the DER INTEGER sign byte(s) so n/e are raw magnitudes */
    const uint8_t *n = mod.value; size_t nlen = mod.len;
    while (nlen > 1 && n[0] == 0x00) { n++; nlen--; }
    const uint8_t *e = exp.value; size_t elen = exp.len;
    while (elen > 1 && e[0] == 0x00) { e++; elen--; }

    if (cert->signature.len != nlen) return X509_VERIFY_BAD_SIGNATURE;  /* k must match */
    if (rsa_pkcs1_v15_verify(n, nlen, e, elen,
                             cert->signature.p, cert->signature.len,
                             di, sizeof di) != 0)
        return X509_VERIFY_BAD_SIGNATURE;
    return X509_VERIFY_OK;
}

int x509_verify_signature(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    if (x509_slice_eq(&cert->sig_oid, OID_SHA256_RSA, sizeof OID_SHA256_RSA))
        return verify_rsa_sha256(cert, ik, iklen);

    if (x509_slice_eq(&cert->sig_oid, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256))
        return X509_VERIFY_UNSUPPORTED;     /* ECDSA: a later step */

    return X509_VERIFY_UNSUPPORTED;
}
