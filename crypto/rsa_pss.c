/* RSASSA-PSS verification — see rsa_pss.h. */
#include "rsa_pss.h"
#include "rsa.h"
#include "mgf1.h"
#include "sha256.h"

#define HLEN 32      /* SHA-256 digest length */
#define SLEN 32      /* salt length (TLS 1.3 mandates == hash length) */

static size_t bytes_bitlen(const uint8_t *b, size_t len)
{
    size_t i = 0;
    while (i < len && b[i] == 0) i++;
    if (i == len) return 0;
    size_t bits = (len - i - 1) * 8;
    uint8_t top = b[i];
    while (top) { bits++; top >>= 1; }
    return bits;
}

int rsa_pss_sha256_verify(const uint8_t *n, size_t nlen,
                          const uint8_t *e, size_t elen,
                          const uint8_t *sig, size_t siglen,
                          const uint8_t hash[32])
{
    uint8_t em[RSA_MAX_BYTES];
    if (siglen != nlen) return -1;
    int k = rsa_public(n, nlen, e, elen, sig, siglen, em, sizeof em);   /* EM = sig^e mod n, k bytes */
    if (k < 0) return -1;

    /* EMSA-PSS-VERIFY (RFC 8017 §9.1.2) */
    size_t modbits = bytes_bitlen(n, nlen);
    if (modbits == 0) return -1;
    size_t embits = modbits - 1;
    size_t emlen = (embits + 7) / 8;
    if (emlen > (size_t)k) return -1;

    /* the encoded message is the low emlen bytes; any bytes above it must be 0 */
    for (size_t i = 0; i + emlen < (size_t)k; i++) if (em[i] != 0) return -1;
    const uint8_t *EM = em + ((size_t)k - emlen);

    if (emlen < HLEN + SLEN + 2) return -1;
    if (EM[emlen - 1] != 0xbc) return -1;

    size_t dblen = emlen - HLEN - 1;
    const uint8_t *maskedDB = EM;
    const uint8_t *H = EM + dblen;

    size_t leadbits = 8 * emlen - embits;       /* top bits of maskedDB[0] must be 0 */
    if (leadbits && (maskedDB[0] >> (8 - leadbits))) return -1;

    uint8_t db[RSA_MAX_BYTES];
    mgf1_sha256(H, HLEN, db, dblen);
    for (size_t i = 0; i < dblen; i++) db[i] ^= maskedDB[i];
    if (leadbits) db[0] &= (uint8_t)(0xff >> leadbits);

    /* DB must be 0x00.. || 0x01 || salt */
    size_t i = 0;
    while (i < dblen - SLEN - 1 && db[i] == 0) i++;
    if (i != dblen - SLEN - 1 || db[i] != 0x01) return -1;
    const uint8_t *salt = db + dblen - SLEN;

    /* H' = SHA-256(0x00 x8 || mHash || salt) */
    uint8_t mprime[8 + HLEN + SLEN];
    for (int j = 0; j < 8; j++) mprime[j] = 0;
    for (int j = 0; j < HLEN; j++) mprime[8 + j] = hash[j];
    for (size_t j = 0; j < SLEN; j++) mprime[8 + HLEN + j] = salt[j];
    uint8_t hprime[HLEN];
    sha256(mprime, sizeof mprime, hprime);

    int ok = 1;
    for (int j = 0; j < HLEN; j++) ok &= (H[j] == hprime[j]);
    return ok ? 0 : -1;
}
