/* X.509 signature verification — see verify_cert.h. */
#include "verify_cert.h"
#include "asn1.h"
#include "sha256.h"
#include "sha384.h"
#include "rsa.h"
#include "ecdsa.h"
#include "ecdsa384.h"

/* signatureAlgorithm OIDs (raw DER contents) */
static const uint8_t OID_SHA256_RSA[]   = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_ECDSA_SHA256[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };
static const uint8_t OID_ECDSA_SHA384[] = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03 };

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

/* ECDSA-with-SHA-384 over the TBSCertificate. The issuer's EC subjectPublicKey
 * (ik) is the uncompressed point 0x04 || X || Y; ecdsa_p384_verify validates it
 * fully (97 bytes, on-curve P-384, correct subgroup) and parses the DER signature
 * strictly, so a non-P-384 key reached via a spoofed sig_oid fails the decode. */
static int verify_ecdsa_sha384(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    uint8_t hash[48];
    sha384(cert->tbs.p, cert->tbs.len, hash);
    if (ecdsa_p384_verify(ik, iklen, hash, cert->signature.p, cert->signature.len) != 0)
        return X509_VERIFY_BAD_SIGNATURE;
    return X509_VERIFY_OK;
}

int x509_verify_signature(const x509_cert *cert, const uint8_t *ik, size_t iklen)
{
    if (x509_slice_eq(&cert->sig_oid, OID_SHA256_RSA, sizeof OID_SHA256_RSA))
        return verify_rsa_sha256(cert, ik, iklen);

    if (x509_slice_eq(&cert->sig_oid, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256))
        return verify_ecdsa_sha256(cert, ik, iklen);

    if (x509_slice_eq(&cert->sig_oid, OID_ECDSA_SHA384, sizeof OID_ECDSA_SHA384))
        return verify_ecdsa_sha384(cert, ik, iklen);

    return X509_VERIFY_UNSUPPORTED;
}

#define X509_MAX_DEPTH 8       /* bound on path length (also stops issuer cycles) */

/* Two Names are the same iff their DER encodings match byte-for-byte. RFC 5280
 * permits this binary comparison when the encodings agree, which they do for
 * CA-issued certs (the issuer field is copied from the CA's subject). It can only
 * fail closed — reject a chain whose DNs were re-encoded — never accept a wrong
 * one. */
static int name_eq(const x509_slice *a, const x509_slice *b)
{
    if (a->len != b->len || a->len == 0) return 0;
    for (size_t i = 0; i < a->len; i++) if (a->p[i] != b->p[i]) return 0;
    return 1;
}

/* A certificate used as an issuer (an intermediate) must be allowed to sign
 * certificates: basicConstraints cA = TRUE, and — if a KeyUsage is present — the
 * keyCertSign bit. (A KeyUsage absent does not restrict usage.) */
static int may_sign_certs(const x509_cert *ca)
{
    if (!ca->is_ca) return 0;
    if (ca->has_key_usage && !ca->key_cert_sign) return 0;
    return 1;
}

int x509_verify_chain(const x509_cert *chain, size_t chain_count,
                      const x509_cert *roots, size_t root_count)
{
    if (chain_count == 0) return X509_VERIFY_UNTRUSTED;

    const x509_cert *cur = &chain[0];                 /* end-entity certificate */
    int bad_ca = 0, bad_sig = 0;       /* "found the issuer by name but it was unusable" reasons */

    for (int depth = 0; depth < X509_MAX_DEPTH; depth++) {
        /* Terminal: is cur signed by a trusted root? Roots are anchors, so they
         * are not themselves subject to the basicConstraints/keyUsage check. */
        for (size_t i = 0; i < root_count; i++) {
            if (!name_eq(&cur->issuer_raw, &roots[i].subject_raw)) continue;
            if (x509_verify_signature(cur, roots[i].spki_key.p, roots[i].spki_key.len) == X509_VERIFY_OK)
                return X509_VERIFY_OK;
            bad_sig = 1;                                  /* name matched, signature did not */
        }

        /* Otherwise climb one link through an intermediate in the chain. */
        const x509_cert *next = 0;
        for (size_t i = 1; i < chain_count; i++) {
            const x509_cert *ca = &chain[i];
            if (ca == cur) continue;
            if (!name_eq(&cur->issuer_raw, &ca->subject_raw)) continue;
            if (x509_verify_signature(cur, ca->spki_key.p, ca->spki_key.len) != X509_VERIFY_OK) {
                bad_sig = 1; continue;                   /* name matched, signature did not */
            }
            if (!may_sign_certs(ca)) { bad_ca = 1; continue; }   /* valid signer, but not a CA */
            next = ca; break;
        }
        if (!next) return bad_ca  ? X509_VERIFY_BAD_CA :
                          bad_sig ? X509_VERIFY_BAD_SIGNATURE : X509_VERIFY_UNTRUSTED;
        cur = next;
    }
    return X509_VERIFY_UNTRUSTED;   /* path too long */
}

int x509_check_validity(const x509_cert *cert, uint64_t now)
{
    if (now < cert->not_before) return X509_VALID_NOT_YET;
    if (now > cert->not_after)  return X509_VALID_EXPIRED;
    return X509_VALID_OK;
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

/* Case-insensitive compare of a C string `a` against a (ptr,len) slice `b`. The
 * SAN entries are now views into the DER (not NUL-terminated), so matching works
 * on the explicit length. */
static int ci_equal_slice(const char *a, const uint8_t *b, size_t blen)
{
    size_t i = 0;
    while (a[i] && i < blen) { if (lower(a[i]) != lower((char)b[i])) return 0; i++; }
    return a[i] == 0 && i == blen;
}

int x509_check_hostname(const x509_cert *cert, const char *host)
{
    for (int i = 0; i < cert->san_count; i++) {
        const uint8_t *san = cert->san_dns[i].p;
        size_t slen = cert->san_dns[i].len;
        if (slen >= 2 && san[0] == '*' && san[1] == '.') {
            /* wildcard matches exactly one left-most label: strip the first
             * label of host and compare the remainder to the part after "*." */
            const char *dot = host;
            while (*dot && *dot != '.') dot++;
            if (*dot != '.' || dot == host) continue;   /* host needs a non-empty first label */
            if (ci_equal_slice(dot + 1, san + 2, slen - 2)) return 0;
        } else {
            if (ci_equal_slice(host, san, slen)) return 0;
        }
    }
    return -1;
}
