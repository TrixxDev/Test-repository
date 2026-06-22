/* HKDF (RFC 5869) over HMAC-SHA256 — see hkdf.h. */
#include "hkdf.h"
#include "hmac_sha256.h"

void hkdf_extract(const void *salt, size_t saltlen,
                  const void *ikm, size_t ikmlen,
                  uint8_t prk[HKDF_HASH_LEN])
{
    uint8_t zero[HKDF_HASH_LEN];
    if (!salt || saltlen == 0) {           /* RFC 5869: salt defaults to HashLen zeros */
        for (int i = 0; i < HKDF_HASH_LEN; i++) zero[i] = 0;
        salt = zero;
        saltlen = HKDF_HASH_LEN;
    }
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

int hkdf_expand(const uint8_t prk[HKDF_HASH_LEN],
                const void *info, size_t infolen,
                uint8_t *okm, size_t len)
{
    const uint8_t *ip = (const uint8_t *)info;
    uint8_t t[HKDF_HASH_LEN];                       /* T(i-1), then T(i) */
    uint8_t buf[HKDF_HASH_LEN + HKDF_MAX_INFO + 1]; /* T(i-1) | info | counter */
    size_t tlen = 0;                               /* bytes of T(i-1) (0 for T(1)) */
    size_t done = 0;
    uint8_t counter = 1;

    if (len > 255 * HKDF_HASH_LEN) return -1;       /* RFC 5869 §2.3 limit */
    if (infolen > HKDF_MAX_INFO) return -1;

    while (done < len) {
        size_t p = 0;
        for (size_t i = 0; i < tlen; i++)    buf[p++] = t[i];   /* T(i-1) */
        for (size_t i = 0; i < infolen; i++) buf[p++] = ip[i];  /* info   */
        buf[p++] = counter;                                     /* i      */
        hmac_sha256(prk, HKDF_HASH_LEN, buf, p, t);
        tlen = HKDF_HASH_LEN;

        size_t n = len - done;
        if (n > HKDF_HASH_LEN) n = HKDF_HASH_LEN;
        for (size_t i = 0; i < n; i++) okm[done + i] = t[i];
        done += n;
        counter++;
    }
    return 0;
}
