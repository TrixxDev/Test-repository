/* X.509 certificate parser (RFC 5280) — v1, no cryptography.
 *
 * Turns a DER certificate into a flat `x509_cert` of the fields a TLS client
 * actually needs, over the bounds-checked ASN.1 reader (x509/asn1.c). It makes no
 * trust decision and verifies no signature — that is the next layer. Scope is
 * deliberately tight: only the Common Name is pulled out of the issuer/subject
 * Distinguished Names (the rest of the DN is ignored), validity is normalized to
 * Unix time on the spot, and Subject Alternative Name dNSName entries are
 * collected because hostname matching uses SAN, not CN.
 *
 * The slices below are *views into the caller's DER buffer*, not copies, so that
 * buffer must outlive the x509_cert. Freestanding: no allocation, no OS calls. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define X509_MAX_SAN   8
#define X509_CN_MAX    128

/* public-key algorithm (from SubjectPublicKeyInfo) */
#define X509_PK_UNKNOWN 0
#define X509_PK_RSA     1
#define X509_PK_EC      2       /* EC on prime256v1 (P-256) */
#define X509_PK_EC384   3       /* EC on secp384r1 (P-384) */

/* A view into the DER buffer (pointer + length), never owning memory. */
typedef struct { const uint8_t *p; size_t len; } x509_slice;

typedef struct {
    uint32_t   version;            /* raw X.509 version: 0=v1, 1=v2, 2=v3 */
    x509_slice serial;             /* serialNumber INTEGER contents (raw) */

    char issuer_cn[X509_CN_MAX];   /* issuer Common Name (diagnostic only) */
    char subject_cn[X509_CN_MAX];  /* subject Common Name (diagnostic only) */

    x509_slice issuer_raw;         /* full issuer Name element (tag+len+value), for chaining */
    x509_slice subject_raw;        /* full subject Name element (tag+len+value), for chaining */

    uint64_t not_before;           /* validity, normalized to Unix time */
    uint64_t not_after;

    int  san_count;                /* number of dNSName entries captured */
    x509_slice san_dns[X509_MAX_SAN];  /* dNSName SANs as views into the DER (not copied) */

    int        is_ca;              /* basicConstraints cA = TRUE (absent => FALSE) */
    int        has_key_usage;      /* a KeyUsage extension was present */
    int        key_cert_sign;      /* KeyUsage keyCertSign bit set */

    int        pubkey_algo;        /* X509_PK_* */
    x509_slice spki;               /* full SubjectPublicKeyInfo (tag+len+value) */
    x509_slice spki_key;           /* subjectPublicKey BIT STRING, unused-bits octet dropped */

    x509_slice tbs;                /* raw TBSCertificate (tag+len+value) — what the signature covers */
    x509_slice signature;         /* signatureValue, unused-bits octet dropped */
    x509_slice sig_oid;           /* signatureAlgorithm OID contents (raw) */
} x509_cert;

/* Parse a DER certificate into *out. Returns 0 on success, -1 if malformed.
 * On success, all slices in *out point into `der` (which must stay valid). */
int x509_parse(const uint8_t *der, size_t len, x509_cert *out);

/* Convenience: does a captured slice equal the given raw OID bytes? */
int x509_slice_eq(const x509_slice *s, const uint8_t *bytes, size_t n);
