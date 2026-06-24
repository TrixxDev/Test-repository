/* X.509 certificate parser — see x509.h. No cryptography here. */
#include "x509.h"
#include "asn1.h"

/* OIDs we recognize (raw DER contents, no tag/length). */
static const uint8_t OID_CN[]      = { 0x55, 0x04, 0x03 };                              /* 2.5.4.3 commonName */
static const uint8_t OID_SAN[]     = { 0x55, 0x1d, 0x11 };                              /* 2.5.29.17 subjectAltName */
static const uint8_t OID_RSA[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 }; /* rsaEncryption */
static const uint8_t OID_EC[]      = { 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01 };           /* id-ecPublicKey */
static const uint8_t OID_P256[]    = { 0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };      /* prime256v1 (P-256) */

int x509_slice_eq(const x509_slice *s, const uint8_t *bytes, size_t n)
{
    if (s->len != n) return 0;
    for (size_t i = 0; i < n; i++) if (s->p[i] != bytes[i]) return 0;
    return 1;
}

static void copy_str(char *dst, size_t cap, const uint8_t *src, size_t len)
{
    size_t n = len < cap - 1 ? len : cap - 1;
    for (size_t i = 0; i < n; i++) dst[i] = (char)src[i];
    dst[n] = 0;
}

/* days since the Unix epoch for a proleptic-Gregorian date (Hinnant's algorithm) */
static int64_t days_from_civil(int y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int yoe = (int)(y - era * 400);
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int two_digits(const uint8_t *p, int *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return -1;
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return 0;
}

/* Parse a UTCTime/GeneralizedTime (UTC, 'Z' form only) into Unix seconds. */
static int parse_time(const asn1_tlv *t, uint64_t *out)
{
    const uint8_t *p = t->value;
    int year, mo, d, h, mi, s, tmp;

    if (t->tag == ASN1_UTCTIME) {
        if (t->len != 13 || t->value[12] != 'Z') return -1;
        if (two_digits(p, &tmp)) return -1;
        year = tmp < 50 ? 2000 + tmp : 1900 + tmp;
        p += 2;
    } else if (t->tag == ASN1_GENERALIZEDTIME) {
        if (t->len != 15 || t->value[14] != 'Z') return -1;
        int c, yy;
        if (two_digits(p, &c) || two_digits(p + 2, &yy)) return -1;
        year = c * 100 + yy;
        p += 4;
    } else {
        return -1;
    }

    if (two_digits(p, &mo) || two_digits(p + 2, &d) || two_digits(p + 4, &h) ||
        two_digits(p + 6, &mi) || two_digits(p + 8, &s)) return -1;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return -1;

    *out = (uint64_t)(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + s);
    return 0;
}

/* Extract the Common Name from a Name (RDNSequence). Leaves cn empty if absent. */
static int parse_name_cn(const asn1_tlv *name, char *cn, size_t cap)
{
    cn[0] = 0;
    asn1_cursor rdns; asn1_cursor_init(&rdns, name->value, name->len);
    while (!asn1_cursor_empty(&rdns)) {
        asn1_cursor set;
        if (asn1_open(&rdns, ASN1_SET, &set) != 0) return -1;
        while (!asn1_cursor_empty(&set)) {
            asn1_cursor atv;
            if (asn1_open(&set, ASN1_SEQUENCE, &atv) != 0) return -1;
            asn1_tlv type, val;
            if (asn1_next(&atv, &type) != 0) return -1;
            if (asn1_next(&atv, &val) != 0) return -1;
            if (asn1_oid_equals(&type, OID_CN, sizeof OID_CN))
                copy_str(cn, cap, val.value, val.len);   /* last CN wins */
        }
    }
    return 0;
}

/* Walk the extensions, collecting SubjectAltName dNSName entries. */
static int parse_extensions(asn1_cursor *tc, x509_cert *out)
{
    uint8_t tag;
    if (asn1_peek_tag(tc, &tag) != 0) return 0;                       /* no extensions */
    if (tag != (ASN1_CONTEXT | ASN1_CONSTRUCTED | 3)) return 0;

    asn1_cursor explicit_wrap, exts;
    if (asn1_open(tc, ASN1_CONTEXT | ASN1_CONSTRUCTED | 3, &explicit_wrap) != 0) return -1;
    if (asn1_open(&explicit_wrap, ASN1_SEQUENCE, &exts) != 0) return -1;

    while (!asn1_cursor_empty(&exts)) {
        asn1_cursor ext;
        if (asn1_open(&exts, ASN1_SEQUENCE, &ext) != 0) return -1;
        asn1_tlv extid;
        if (asn1_next(&ext, &extid) != 0) return -1;

        uint8_t t2;                                                   /* optional critical BOOLEAN */
        if (asn1_peek_tag(&ext, &t2) == 0 && t2 == ASN1_BOOLEAN) {
            asn1_tlv crit;
            if (asn1_next(&ext, &crit) != 0) return -1;
        }

        asn1_tlv extval;
        if (asn1_expect(&ext, ASN1_OCTET_STRING, &extval) != 0) return -1;

        if (!asn1_oid_equals(&extid, OID_SAN, sizeof OID_SAN)) continue;

        /* extnValue wraps GeneralNames ::= SEQUENCE OF GeneralName */
        asn1_cursor wrap, gns;
        asn1_cursor_init(&wrap, extval.value, extval.len);
        if (asn1_open(&wrap, ASN1_SEQUENCE, &gns) != 0) return -1;
        while (!asn1_cursor_empty(&gns)) {
            asn1_tlv gn;
            if (asn1_next(&gns, &gn) != 0) return -1;
            if (gn.tag == (ASN1_CONTEXT | 2)) {                      /* dNSName [2] IMPLICIT IA5String */
                if (out->san_count < X509_MAX_SAN)
                    copy_str(out->san_dns[out->san_count++], X509_SAN_MAX, gn.value, gn.len);
            }
        }
    }
    return 0;
}

int x509_parse(const uint8_t *der, size_t len, x509_cert *out)
{
    for (size_t i = 0; i < sizeof *out; i++) ((uint8_t *)out)[i] = 0;

    asn1_cursor c, cert;
    asn1_cursor_init(&c, der, len);
    if (asn1_open(&c, ASN1_SEQUENCE, &cert) != 0) return -1;          /* Certificate */
    if (!asn1_cursor_empty(&c)) return -1;                            /* trailing garbage */

    /* tbsCertificate — capture the full element (tag+len+value) for verification */
    const uint8_t *tbs_start = cert.p;
    asn1_tlv tbs;
    if (asn1_expect(&cert, ASN1_SEQUENCE, &tbs) != 0) return -1;
    out->tbs.p = tbs_start; out->tbs.len = (size_t)(cert.p - tbs_start);

    /* signatureAlgorithm { OID, params } */
    asn1_cursor sigalg;
    if (asn1_open(&cert, ASN1_SEQUENCE, &sigalg) != 0) return -1;
    asn1_tlv sigoid;
    if (asn1_next(&sigalg, &sigoid) != 0 || sigoid.tag != ASN1_OID) return -1;
    out->sig_oid.p = sigoid.value; out->sig_oid.len = sigoid.len;

    /* signatureValue BIT STRING (drop the unused-bits octet, which must be 0) */
    asn1_tlv sig;
    if (asn1_expect(&cert, ASN1_BIT_STRING, &sig) != 0) return -1;
    if (sig.len < 1 || sig.value[0] != 0) return -1;
    out->signature.p = sig.value + 1; out->signature.len = sig.len - 1;
    if (!asn1_cursor_empty(&cert)) return -1;

    /* ---- TBSCertificate ---- */
    asn1_cursor tc;
    asn1_cursor_init(&tc, tbs.value, tbs.len);

    /* version [0] EXPLICIT INTEGER DEFAULT v1 */
    uint8_t tag;
    out->version = 0;
    if (asn1_peek_tag(&tc, &tag) == 0 && tag == (ASN1_CONTEXT | ASN1_CONSTRUCTED | 0)) {
        asn1_cursor vc;
        if (asn1_open(&tc, ASN1_CONTEXT | ASN1_CONSTRUCTED | 0, &vc) != 0) return -1;
        asn1_tlv v; uint64_t vv;
        if (asn1_next(&vc, &v) != 0 || asn1_get_uint(&v, &vv) != 0) return -1;
        out->version = (uint32_t)vv;
    }

    /* serialNumber */
    asn1_tlv serial;
    if (asn1_expect(&tc, ASN1_INTEGER, &serial) != 0) return -1;
    out->serial.p = serial.value; out->serial.len = serial.len;

    /* signature AlgorithmIdentifier (inner copy; ignored, must be a SEQUENCE) */
    asn1_tlv inner_sig;
    if (asn1_expect(&tc, ASN1_SEQUENCE, &inner_sig) != 0) return -1;

    /* issuer Name */
    asn1_tlv issuer;
    if (asn1_expect(&tc, ASN1_SEQUENCE, &issuer) != 0) return -1;
    if (parse_name_cn(&issuer, out->issuer_cn, sizeof out->issuer_cn) != 0) return -1;

    /* validity { notBefore, notAfter } */
    asn1_cursor val;
    if (asn1_open(&tc, ASN1_SEQUENCE, &val) != 0) return -1;
    asn1_tlv nb, na;
    if (asn1_next(&val, &nb) != 0 || parse_time(&nb, &out->not_before) != 0) return -1;
    if (asn1_next(&val, &na) != 0 || parse_time(&na, &out->not_after) != 0) return -1;

    /* subject Name */
    asn1_tlv subject;
    if (asn1_expect(&tc, ASN1_SEQUENCE, &subject) != 0) return -1;
    if (parse_name_cn(&subject, out->subject_cn, sizeof out->subject_cn) != 0) return -1;

    /* subjectPublicKeyInfo — capture the full element */
    const uint8_t *spki_start = tc.p;
    asn1_cursor spki;
    if (asn1_open(&tc, ASN1_SEQUENCE, &spki) != 0) return -1;
    out->spki.p = spki_start; out->spki.len = (size_t)(tc.p - spki_start);

    asn1_cursor pkalg;
    if (asn1_open(&spki, ASN1_SEQUENCE, &pkalg) != 0) return -1;
    asn1_tlv pkoid;
    if (asn1_next(&pkalg, &pkoid) != 0 || pkoid.tag != ASN1_OID) return -1;
    if (asn1_oid_equals(&pkoid, OID_RSA, sizeof OID_RSA)) {
        out->pubkey_algo = X509_PK_RSA;
    } else if (asn1_oid_equals(&pkoid, OID_EC, sizeof OID_EC)) {
        /* For EC the AlgorithmIdentifier parameters carry the namedCurve OID.
         * We support prime256v1 (P-256) only, so a key on any other curve is
         * treated as unknown rather than letting a non-P-256 point reach the
         * P-256 verifier. */
        asn1_tlv curve;
        if (asn1_next(&pkalg, &curve) == 0 && curve.tag == ASN1_OID &&
            asn1_oid_equals(&curve, OID_P256, sizeof OID_P256))
            out->pubkey_algo = X509_PK_EC;
        else
            out->pubkey_algo = X509_PK_UNKNOWN;
    } else {
        out->pubkey_algo = X509_PK_UNKNOWN;
    }

    asn1_tlv pk;
    if (asn1_expect(&spki, ASN1_BIT_STRING, &pk) != 0) return -1;
    if (pk.len < 1 || pk.value[0] != 0) return -1;
    out->spki_key.p = pk.value + 1; out->spki_key.len = pk.len - 1;

    /* skip optional issuerUniqueID [1] / subjectUniqueID [2], then extensions [3] */
    while (asn1_peek_tag(&tc, &tag) == 0 &&
           (tag == (ASN1_CONTEXT | 1) || tag == (ASN1_CONTEXT | 2))) {
        asn1_tlv skip;
        if (asn1_next(&tc, &skip) != 0) return -1;
    }
    if (parse_extensions(&tc, out) != 0) return -1;

    return 0;
}
