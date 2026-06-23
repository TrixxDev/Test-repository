/* ECDSA-P256-SHA256 verification — see ecdsa.h. */
#include "ecdsa.h"
#include "p256_field.h"
#include "p256_scalar.h"
#include "p256_point.h"

/* ---- strict X9.62 DER ECDSA-Sig-Value parser ----
 * SEQUENCE { r INTEGER, s INTEGER }. Rejects: trailing bytes, non-minimal or
 * indefinite lengths, negative integers, non-minimal leading zeros, and
 * magnitudes over 32 bytes. r/s are returned big-endian, left-padded to 32. */

/* Read a DER length at der[*pos], strict (minimal short/long form, no indefinite).
 * Returns the length, or -1 on error; advances *pos past the length octets. */
static long der_len(const uint8_t *der, size_t len, size_t *pos)
{
    if (*pos >= len) return -1;
    uint8_t b = der[(*pos)++];
    if (b < 0x80) return b;                         /* short form */
    int nb = b & 0x7f;
    if (nb == 0 || nb > 4) return -1;               /* indefinite / too large */
    long v = 0;
    for (int i = 0; i < nb; i++) {
        if (*pos >= len) return -1;
        v = (v << 8) | der[(*pos)++];
    }
    if (v < 0x80) return -1;                         /* non-minimal long form */
    return v;
}

/* Parse one INTEGER at der[*pos] into a 32-byte big-endian buffer. */
static int der_int(const uint8_t *der, size_t len, size_t *pos, uint8_t out[32])
{
    if (*pos >= len || der[(*pos)++] != 0x02) return -1;   /* INTEGER tag */
    long ilen = der_len(der, len, pos);
    if (ilen < 1 || (size_t)(*pos) + (size_t)ilen > len) return -1;
    const uint8_t *p = der + *pos;
    *pos += (size_t)ilen;

    if (p[0] & 0x80) return -1;                            /* negative -> reject */
    if (ilen >= 2 && p[0] == 0x00 && !(p[1] & 0x80)) return -1; /* non-minimal zero pad */
    /* strip a single legal leading zero */
    size_t off = (ilen >= 2 && p[0] == 0x00) ? 1 : 0;
    size_t mag = (size_t)ilen - off;
    if (mag > 32) return -1;                               /* too big for P-256 */
    for (int i = 0; i < 32; i++) out[i] = 0;
    for (size_t i = 0; i < mag; i++) out[32 - mag + i] = p[off + i];
    return 0;
}

int ecdsa_sig_from_der(const uint8_t *der, size_t len, uint8_t r[32], uint8_t s[32])
{
    size_t pos = 0;
    if (len < 2 || der[pos++] != 0x30) return -1;          /* SEQUENCE */
    long seqlen = der_len(der, len, &pos);
    if (seqlen < 0 || pos + (size_t)seqlen != len) return -1;  /* exact, no trailing */
    if (der_int(der, len, &pos, r) != 0) return -1;
    if (der_int(der, len, &pos, s) != 0) return -1;
    if (pos != len) return -1;                              /* no trailing inside SEQUENCE */
    return 0;
}

int ecdsa_p256_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t hash[32],
                      const uint8_t *sig_der, size_t sig_len)
{
    p256_point Q, G, R1, R2, R;
    sc r, s, e, w, u1, u2;
    uint8_t rb[32], sb[32];
    fe xr; uint8_t xrb[32]; sc xrn;

    if (p256_pubkey_decode(&Q, pub, pub_len) != 0) return -1;
    if (ecdsa_sig_from_der(sig_der, sig_len, rb, sb) != 0) return -1;

    /* r, s must be in [1, n-1] */
    if (sc_from_bytes(&r, rb) != 0 || sc_is_zero(&r)) return -1;
    if (sc_from_bytes(&s, sb) != 0 || sc_is_zero(&s)) return -1;

    sc_reduce(&e, hash);                       /* e = hash mod n */
    sc_inv(&w, &s);                            /* w = s^-1 mod n */
    sc_mul(&u1, &e, &w);                       /* u1 = e*w */
    sc_mul(&u2, &r, &w);                       /* u2 = r*w */

    p256_base_point(&G);
    p256_scalar_mul(&R1, &u1, &G);             /* u1*G */
    p256_scalar_mul(&R2, &u2, &Q);             /* u2*Q */
    p256_add(&R, &R1, &R2);                     /* R = u1*G + u2*Q */
    if (p256_is_infinity(&R)) return -1;

    {
        fe yr; (void)yr;
        if (p256_to_affine(&xr, &yr, &R) != 0) return -1;
    }
    fe_to_bytes(xrb, &xr);
    sc_reduce(&xrn, xrb);                       /* v = x_R mod n */
    return sc_equal(&xrn, &r) ? 0 : -1;        /* accept iff v == r */
}
