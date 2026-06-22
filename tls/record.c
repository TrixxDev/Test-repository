/* TLS 1.3 record layer (RFC 8446 §5) — see record.h. */
#include "record.h"
#include "chacha20poly1305.h"

void tls_record_init(tls_record_keys *k, const uint8_t key[32], const uint8_t iv[12])
{
    for (int i = 0; i < 32; i++) k->key[i] = key[i];
    for (int i = 0; i < 12; i++) k->iv[i]  = iv[i];
    k->seq = 0;
}

void tls_record_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq)
{
    for (int i = 0; i < 12; i++) nonce[i] = iv[i];
    /* XOR the 64-bit sequence number, big-endian, into the rightmost 8 bytes */
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

int tls_record_seal(tls_record_keys *k, uint8_t type,
                    const uint8_t *plaintext, size_t ptlen,
                    uint8_t *out, size_t outcap)
{
    if (ptlen > TLS_RECORD_MAX_PLAINTEXT) return -1;

    size_t inner_len = ptlen + 1;                       /* content || real type */
    size_t enc_len   = inner_len + TLS_RECORD_TAG_LEN;  /* ciphertext || tag    */
    size_t total     = TLS_RECORD_HEADER_LEN + enc_len;
    if (total > outcap) return -1;

    /* TLSCiphertext header — also the AEAD additional_data (§5.2) */
    out[0] = TLS_CONTENT_APPLICATION_DATA;              /* opaque_type */
    out[1] = 0x03; out[2] = 0x03;                       /* legacy_record_version */
    out[3] = (uint8_t)(enc_len >> 8);
    out[4] = (uint8_t)(enc_len & 0xff);

    /* TLSInnerPlaintext = content || type, built in place at out+5 (no padding) */
    uint8_t *inner = out + TLS_RECORD_HEADER_LEN;
    for (size_t i = 0; i < ptlen; i++) inner[i] = plaintext[i];
    inner[ptlen] = type;

    uint8_t nonce[12];
    tls_record_nonce(nonce, k->iv, k->seq);

    /* encrypt in place; the tag lands right after the ciphertext. AAD = header. */
    chacha20poly1305_seal(inner, inner + inner_len, k->key, nonce, out, 5, inner, inner_len);

    k->seq++;
    return (int)total;
}

int tls_record_open(tls_record_keys *k,
                    const uint8_t *record, size_t reclen,
                    uint8_t *out, size_t outcap, uint8_t *out_type)
{
    if (reclen < TLS_RECORD_HEADER_LEN) return -1;
    if (record[0] != TLS_CONTENT_APPLICATION_DATA) return -1;   /* TLS 1.3 wire type */

    size_t enc_len = ((size_t)record[3] << 8) | record[4];
    if (enc_len < TLS_RECORD_TAG_LEN + 1) return -1;            /* need >= 1 inner byte */
    if (reclen != TLS_RECORD_HEADER_LEN + enc_len) return -1;

    size_t inner_len = enc_len - TLS_RECORD_TAG_LEN;
    if (inner_len > outcap) return -1;

    uint8_t nonce[12];
    tls_record_nonce(nonce, k->iv, k->seq);

    const uint8_t *ct  = record + TLS_RECORD_HEADER_LEN;
    const uint8_t *tag = ct + inner_len;
    /* AAD = the on-wire header (§5.2). Verify-before-decrypt is in the AEAD. */
    if (chacha20poly1305_open(out, k->key, nonce, record, 5, ct, inner_len, tag) != 0)
        return -1;

    /* strip trailing zero padding; the last non-zero byte is the content type */
    size_t n = inner_len;
    while (n > 0 && out[n - 1] == 0) n--;
    if (n == 0) return -1;                                      /* all zeros: malformed */

    *out_type = out[n - 1];
    k->seq++;
    return (int)(n - 1);                                        /* content length */
}
