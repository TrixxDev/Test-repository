/* RSA public-key operations — see rsa.h. */
#include "rsa.h"
#include "bignum.h"

int rsa_public(const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen,
               const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    if (nlen == 0 || nlen > RSA_MAX_BYTES || outlen < nlen) return -1;

    bignum N, E, M, R;
    if (bignum_from_bytes(&N, n, nlen) != 0) return -1;
    if (bignum_from_bytes(&E, e, elen) != 0) return -1;
    if (bignum_from_bytes(&M, in, inlen) != 0) return -1;
    if (bignum_is_zero(&N)) return -1;
    if (bignum_cmp(&M, &N) >= 0) return -1;        /* the input must be reduced mod n */

    bignum_modexp(&R, &M, &E, &N);
    if (bignum_to_bytes(&R, out, nlen) != 0) return -1;
    return (int)nlen;
}

int rsa_pkcs1_v15_verify(const uint8_t *n, size_t nlen,
                         const uint8_t *e, size_t elen,
                         const uint8_t *sig, size_t siglen,
                         const uint8_t *digestinfo, size_t dilen)
{
    uint8_t em[RSA_MAX_BYTES];

    if (siglen != nlen) return -1;                 /* signature length must equal k */
    int k = rsa_public(n, nlen, e, elen, sig, siglen, em, sizeof em);
    if (k < 0) return -1;

    /* EM = 0x00 0x01 | PS (>=8 of 0xFF) | 0x00 | digestinfo */
    if (dilen + 11 > (size_t)k) return -1;
    size_t pslen = (size_t)k - 3 - dilen;

    int ok = 1;
    ok &= (em[0] == 0x00);
    ok &= (em[1] == 0x01);
    for (size_t i = 0; i < pslen; i++)  ok &= (em[2 + i] == 0xFF);
    ok &= (em[2 + pslen] == 0x00);
    for (size_t i = 0; i < dilen; i++)  ok &= (em[3 + pslen + i] == digestinfo[i]);
    return ok ? 0 : -1;
}
