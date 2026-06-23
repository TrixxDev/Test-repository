/* TLS 1.3 Certificate message + PKI glue — see cert.h. */
#include "cert.h"
#include "handshake.h"     /* TLS_HS_CERTIFICATE */
#include "verify_cert.h"

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
