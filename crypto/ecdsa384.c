/* ECDSA-P384-SHA384 verification — see ecdsa384.h.
 * Strict X9.62 DER parser (a private 48-byte copy of the P-256 one) + the
 * standard verification equation over the P-384 field/scalar/point modules. */
#include "ecdsa384.h"
#include "p384_field.h"
#include "p384_scalar.h"
#include "p384_point.h"

/* Read a DER length, strict (minimal short/long form, no indefinite). */
static long der_len(const uint8_t *der, size_t len, size_t *pos)
{
    if (*pos >= len) return -1;
    uint8_t b = der[(*pos)++];
    if (b < 0x80) return b;
    int nb = b & 0x7f;
    if (nb == 0 || nb > 4) return -1;
    long v = 0;
    for (int i = 0; i < nb; i++) {
        if (*pos >= len) return -1;
        v = (v << 8) | der[(*pos)++];
    }
    if (v < 0x80) return -1;                          /* non-minimal long form */
    return v;
}

/* Parse one INTEGER into a 48-byte big-endian buffer. */
static int der_int(const uint8_t *der, size_t len, size_t *pos, uint8_t out[48])
{
    if (*pos >= len || der[(*pos)++] != 0x02) return -1;        /* INTEGER tag */
    long ilen = der_len(der, len, pos);
    if (ilen < 1 || (size_t)(*pos) + (size_t)ilen > len) return -1;
    const uint8_t *p = der + *pos;
    *pos += (size_t)ilen;

    if (p[0] & 0x80) return -1;                                 /* negative -> reject */
    if (ilen >= 2 && p[0] == 0x00 && !(p[1] & 0x80)) return -1; /* non-minimal zero pad */
    size_t off = (ilen >= 2 && p[0] == 0x00) ? 1 : 0;
    size_t mag = (size_t)ilen - off;
    if (mag > 48) return -1;                                    /* too big for P-384 */
    for (int i = 0; i < 48; i++) out[i] = 0;
    for (size_t i = 0; i < mag; i++) out[48 - mag + i] = p[off + i];
    return 0;
}

int ecdsa384_sig_from_der(const uint8_t *der, size_t len, uint8_t r[48], uint8_t s[48])
{
    size_t pos = 0;
    if (len < 2 || der[pos++] != 0x30) return -1;              /* SEQUENCE */
    long seqlen = der_len(der, len, &pos);
    if (seqlen < 0 || pos + (size_t)seqlen != len) return -1;  /* exact, no trailing */
    if (der_int(der, len, &pos, r) != 0) return -1;
    if (der_int(der, len, &pos, s) != 0) return -1;
    if (pos != len) return -1;
    return 0;
}

int ecdsa_p384_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t hash[48],
                      const uint8_t *sig_der, size_t sig_len)
{
    p384_point Q, G, R1, R2, R;
    sc384 r, s, e, w, u1, u2;
    uint8_t rb[48], sb[48];
    fe384 xr; uint8_t xrb[48]; sc384 xrn;

    if (p384_pubkey_decode(&Q, pub, pub_len) != 0) return -1;
    if (ecdsa384_sig_from_der(sig_der, sig_len, rb, sb) != 0) return -1;

    if (sc384_from_bytes(&r, rb) != 0 || sc384_is_zero(&r)) return -1;   /* r in [1,n-1] */
    if (sc384_from_bytes(&s, sb) != 0 || sc384_is_zero(&s)) return -1;   /* s in [1,n-1] */

    sc384_reduce(&e, hash);                    /* e = hash mod n (SHA-384 == 384 bits) */
    sc384_inv(&w, &s);                          /* w = s^-1 mod n */
    sc384_mul(&u1, &e, &w);                     /* u1 = e*w */
    sc384_mul(&u2, &r, &w);                     /* u2 = r*w */

    p384_base_point(&G);
    p384_scalar_mul(&R1, &u1, &G);              /* u1*G */
    p384_scalar_mul(&R2, &u2, &Q);             /* u2*Q */
    p384_add(&R, &R1, &R2);                      /* R = u1*G + u2*Q */
    if (p384_is_infinity(&R)) return -1;

    {
        fe384 yr; (void)yr;
        if (p384_to_affine(&xr, &yr, &R) != 0) return -1;
    }
    fe384_to_bytes(xrb, &xr);
    sc384_reduce(&xrn, xrb);                     /* v = x_R mod n */
    return sc384_equal(&xrn, &r) ? 0 : -1;      /* accept iff v == r */
}
