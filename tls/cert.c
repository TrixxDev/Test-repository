/* TLS 1.3 Certificate message + PKI glue — see cert.h. */
#include "cert.h"
#include "handshake.h"     /* TLS_HS_CERTIFICATE */
#include "verify_cert.h"
#include "sha256.h"
#include "rsa_pss.h"

static uint32_t rd(const uint8_t *p, int n)
{
    uint32_t v = 0;
    for (int i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

int tls_parse_certificate(const uint8_t *msg, size_t len, tls_cert_chain *out)
{
    out->count = 0;
    if (len < 4 || msg[0] != TLS_HS_CERTIFICATE) return -1;
    if (4 + rd(msg + 1, 3) != len) return -1;

    const uint8_t *p = msg + 4, *end = msg + len;

    /* certificate_request_context<0..2^8-1> (empty for server certificates) */
    if (p >= end) return -1;
    uint8_t ctxlen = *p++;
    if ((size_t)(end - p) < ctxlen) return -1;
    p += ctxlen;

    /* certificate_list<0..2^24-1> must fill the rest of the message */
    if (end - p < 3) return -1;
    uint32_t list_len = rd(p, 3); p += 3;
    if ((uint32_t)(end - p) != list_len) return -1;

    /* CertificateEntry: cert_data<1..2^24-1> || extensions<0..2^16-1> */
    while (p < end) {
        if (end - p < 3) return -1;
        uint32_t clen = rd(p, 3); p += 3;
        if (clen == 0 || (uint32_t)(end - p) < clen) return -1;
        const uint8_t *cert_der = p; p += clen;

        if (end - p < 2) return -1;
        uint32_t extlen = rd(p, 2); p += 2;
        if ((uint32_t)(end - p) < extlen) return -1;
        p += extlen;                              /* CertificateEntry extensions ignored (v1) */

        if (out->count < TLS_MAX_CHAIN) {         /* v1 only needs the leaf; skip extras */
            if (x509_parse(cert_der, clen, &out->certs[out->count]) != 0) return -1;
            out->count++;
        }
    }
    return out->count > 0 ? 0 : -1;
}

int tls_verify_certificate_chain(const tls_cert_chain *chain, const char *hostname,
                                 uint64_t now, const x509_cert *roots, size_t root_count)
{
    if (chain->count == 0) return TLS_CERT_MALFORMED;
    const x509_cert *leaf = &chain->certs[0];

    if (x509_verify_chain(leaf, roots, root_count) != X509_VERIFY_OK)
        return TLS_CERT_UNTRUSTED;

    switch (x509_check_validity(leaf, now)) {
        case X509_VALID_NOT_YET: return TLS_CERT_NOT_YET;
        case X509_VALID_EXPIRED: return TLS_CERT_EXPIRED;
        default: break;
    }

    if (hostname && hostname[0] && x509_check_hostname(leaf, hostname) != 0)
        return TLS_CERT_BAD_HOSTNAME;

    return TLS_CERT_OK;
}

/* RFC 8446 §4.4.3 context string for a server CertificateVerify, plus the 64
 * leading 0x20 octets and the 0x00 separator that prefix the transcript hash. */
static const char CV_CONTEXT[] = "TLS 1.3, server CertificateVerify";

int tls_verify_certificate_verify(const uint8_t transcript_hash[32],
                                  uint16_t sig_scheme,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *leaf_spki_key, size_t leaf_spki_key_len)
{
    if (sig_scheme != TLS_SIG_RSA_PSS_RSAE_SHA256) return TLS_CV_UNSUPPORTED;

    /* signed content = 0x20 x64 || context || 0x00 || transcript_hash */
    uint8_t content[64 + sizeof CV_CONTEXT - 1 + 1 + 32];
    size_t off = 0;
    for (int i = 0; i < 64; i++) content[off++] = 0x20;
    for (size_t i = 0; i < sizeof CV_CONTEXT - 1; i++) content[off++] = (uint8_t)CV_CONTEXT[i];
    content[off++] = 0x00;
    for (int i = 0; i < 32; i++) content[off++] = transcript_hash[i];

    uint8_t h[32];
    sha256(content, off, h);

    const uint8_t *n, *e; size_t nlen, elen;
    if (x509_rsa_pubkey(leaf_spki_key, leaf_spki_key_len, &n, &nlen, &e, &elen) != 0)
        return TLS_CV_MALFORMED;

    if (rsa_pss_sha256_verify(n, nlen, e, elen, sig, siglen, h) != 0) return TLS_CV_BAD;
    return TLS_CV_OK;
}
