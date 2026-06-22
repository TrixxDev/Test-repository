/* TLS 1.3 key schedule (RFC 8446 §7.1) — see key_schedule.h. */
#include "key_schedule.h"
#include "hkdf.h"
#include "sha256.h"

static size_t cstrlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

void tls_hkdf_expand_label(uint8_t *out, size_t outlen,
                           const uint8_t secret[TLS_SECRET_LEN],
                           const char *label,
                           const uint8_t *context, size_t ctxlen)
{
    /* struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255>; } */
    static const char prefix[] = "tls13 ";
    const size_t plen = sizeof(prefix) - 1;          /* 6 */
    const size_t llen = cstrlen(label);

    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t p = 0;
    info[p++] = (uint8_t)(outlen >> 8);
    info[p++] = (uint8_t)(outlen & 0xff);
    info[p++] = (uint8_t)(plen + llen);              /* label length octet */
    for (size_t i = 0; i < plen; i++) info[p++] = (uint8_t)prefix[i];
    for (size_t i = 0; i < llen; i++) info[p++] = (uint8_t)label[i];
    info[p++] = (uint8_t)ctxlen;                     /* context length octet */
    for (size_t i = 0; i < ctxlen; i++) info[p++] = context[i];

    hkdf_expand(secret, info, p, out, outlen);
}

void tls_derive_secret(uint8_t out[TLS_SECRET_LEN],
                       const uint8_t secret[TLS_SECRET_LEN],
                       const char *label,
                       const uint8_t thash[TLS_SECRET_LEN])
{
    tls_hkdf_expand_label(out, TLS_SECRET_LEN, secret, label, thash, TLS_SECRET_LEN);
}

void tls_key_schedule_derive(tls_key_schedule *ks,
                             const uint8_t ecdhe[TLS_SECRET_LEN],
                             const uint8_t hello_hash[TLS_SECRET_LEN])
{
    uint8_t zeros[TLS_SECRET_LEN] = {0};
    uint8_t empty_hash[TLS_SECRET_LEN];
    uint8_t derived[TLS_SECRET_LEN];

    sha256("", 0, empty_hash);                       /* Transcript-Hash("") */

    /* Early Secret = HKDF-Extract(0, PSK=0) */
    hkdf_extract(zeros, TLS_SECRET_LEN, zeros, TLS_SECRET_LEN, ks->early_secret);

    /* Handshake Secret = HKDF-Extract(Derive-Secret(Early,"derived",""), ECDHE) */
    tls_derive_secret(derived, ks->early_secret, "derived", empty_hash);
    hkdf_extract(derived, TLS_SECRET_LEN, ecdhe, TLS_SECRET_LEN, ks->handshake_secret);

    /* handshake traffic secrets from the ClientHello..ServerHello transcript */
    tls_derive_secret(ks->client_hs_traffic, ks->handshake_secret, "c hs traffic", hello_hash);
    tls_derive_secret(ks->server_hs_traffic, ks->handshake_secret, "s hs traffic", hello_hash);

    /* Master Secret = HKDF-Extract(Derive-Secret(Handshake,"derived",""), 0) */
    tls_derive_secret(derived, ks->handshake_secret, "derived", empty_hash);
    hkdf_extract(derived, TLS_SECRET_LEN, zeros, TLS_SECRET_LEN, ks->master_secret);
}

void tls_traffic_keys(const uint8_t traffic_secret[TLS_SECRET_LEN],
                      uint8_t *key, size_t keylen,
                      uint8_t *iv, size_t ivlen)
{
    tls_hkdf_expand_label(key, keylen, traffic_secret, "key", 0, 0);
    tls_hkdf_expand_label(iv,  ivlen,  traffic_secret, "iv",  0, 0);
}
