/* X.509 signature verification — see verify_cert.h. */
#include "verify_cert.h"
#include "asn1.h"
#include "sha256.h"
#include "rsa.h"
#include "ecdsa.h"

/* signatureAlgorithm OIDs (raw DER contents) */
static const uint8_t OID_SHA256_RSA[]   = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_ECDSA_SHA256[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };

/* DER DigestInfo prefix for id-sha256 (algorithm + the 32-byte OCTET STRING tag).
 * The 32-byte digest is appended to form the full DigestInfo. */
static const uint8_t SHA256_DIGESTINFO_PREFIX[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};

static void copy(uint8_t *d, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }

int x509_rsa_pubkey(const uint8_t *spki_key, size_t len,
                    const uint8_t **n, size_t *nlen, const uint8_t **e, size_t *elen)
{
    asn1_cursor c, rsa;
    asn1_cursor_init(&c, spki_key, len);
    if (asn1_open(&c, ASN1_SEQUENCE, &rsa) != 0) return -1;
    asn1_tlv mod, exp;
    if (asn1_expect(&rsa, ASN1_INTEGER, &mod) != 0) return -1;
    if (asn1_expect(&rsa, ASN1_INTEGER, &exp) != 0) return -1;

    /* drop the DER INTEGER sign byte(s) so n/e are raw magnitudes */
    const uint8_t *np = mod.value; size_t nl = mod.len;
    while (nl > 1 && np[0] == 0x00) { np++; nl--; }
    const uint8_t *ep = exp.value; size_t el = exp.len;
    while (el > 1 && ep[0] == 0x00) { ep++; el--; }

    *n = np; *nlen = nl; *e = ep; *elen = el;
    return 0;
}

/* RSASSA-PKCS1-v1.5 with SHA-256 over the TBSCertificate. */
static int verify_rsa_sha256(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    /* DigestInfo = prefix || SHA-256(TBSCertificate) */
    uint8_t di[sizeof SHA256_DIGESTINFO_PREFIX + 32];
    copy(di, SHA256_DIGESTINFO_PREFIX, sizeof SHA256_DIGESTINFO_PREFIX);
    sha256(cert->tbs.p, cert->tbs.len, di + sizeof SHA256_DIGESTINFO_PREFIX);

    const uint8_t *n, *e; size_t nlen, elen;
    if (x509_rsa_pubkey(ik, iklen, &n, &nlen, &e, &elen) != 0) return X509_VERIFY_MALFORMED;

    if (cert->signature.len != nlen) return X509_VERIFY_BAD_SIGNATURE;  /* k must match */
    if (rsa_pkcs1_v15_verify(n, nlen, e, elen,
                             cert->signature.p, cert->signature.len,
                             di, sizeof di) != 0)
        return X509_VERIFY_BAD_SIGNATURE;
    return X509_VERIFY_OK;
}

/* ECDSA-with-SHA-256 over the TBSCertificate. For an EC issuer key, the
 * subjectPublicKey BIT STRING contents (ik) are already the uncompressed point
 * 0x04 || X || Y, which is exactly what ecdsa_p256_verify expects: it fully
 * validates the key (length/prefix, coordinates < p, on-curve, correct subgroup)
 * and parses the X9.62 DER signature strictly before checking the equation. So a
 * mismatched key (e.g. an RSA key reached via a spoofed ECDSA sig_oid) fails the
 * key decode rather than being trusted. */
static int verify_ecdsa_sha256(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    uint8_t hash[32];
    sha256(cert->tbs.p, cert->tbs.len, hash);
    if (ecdsa_p256_verify(ik, iklen, hash, cert->signature.p, cert->signature.len) != 0)
        return X509_VERIFY_BAD_SIGNATURE;
    return X509_VERIFY_OK;
}

int x509_verify_signature(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    if (x509_slice_eq(&cert->sig_oid, OID_SHA256_RSA, sizeof OID_SHA256_RSA))
        return verify_rsa_sha256(cert, ik, iklen);

    if (x509_slice_eq(&cert->sig_oid, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256))
        return verify_ecdsa_sha256(cert, ik, iklen);

    return X509_VERIFY_UNSUPPORTED;
}

int x509_verify_chain(const x509_cert *leaf, const x509_cert *roots, size_t root_count)
{
    /* v1: depth 1. A root is trusted if its public key validates the leaf's
     * signature — that cryptographic fact is the trust relationship; name
     * chaining and intermediate CAs come later (the array interface already
     * allows them). */
    for (size_t i = 0; i < root_count; i++)
        if (x509_verify_signature(leaf, roots[i].spki_key.p, roots[i].spki_key.len) == X509_VERIFY_OK)
            return X509_VERIFY_OK;
    return X509_VERIFY_UNTRUSTED;
}

int x509_check_validity(const x509_cert *cert, uint64_t now)
{
    if (now < cert->not_before) return X509_VALID_NOT_YET;
    if (now > cert->not_after)  return X509_VALID_EXPIRED;
    return X509_VALID_OK;
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) { if (lower(*a) != lower(*b)) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

int x509_check_hostname(const x509_cert *cert, const char *host)
{
    for (int i = 0; i < cert->san_count; i++) {
        const char *san = cert->san_dns[i];
        if (san[0] == '*' && san[1] == '.') {
            /* wildcard matches exactly one left-most label: strip the first
             * label of host and compare the remainder to the part after "*." */
            const char *dot = host;
            while (*dot && *dot != '.') dot++;
            if (*dot != '.' || dot == host) continue;   /* host needs a non-empty first label */
            if (ci_equal(dot + 1, san + 2)) return 0;
        } else {
            if (ci_equal(host, san)) return 0;
        }
    }
    return -1;
}
