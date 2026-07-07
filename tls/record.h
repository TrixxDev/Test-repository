/* TLS 1.3 record layer (RFC 8446 §5) over ChaCha20-Poly1305.
 *
 * This is the first piece of the `tls/` layer: pure protocol framing on top of
 * the RFC-verified crypto/ AEAD — per-record nonce from the sequence number
 * (§5.3), additional-data from the record header (§5.2), and the TLSCiphertext
 * wire layout (§5.2). No networking here: bytes in, bytes out, so it is fully
 * testable on the host. The handshake/key-schedule live in sibling files. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* ContentType (RFC 8446 §5.1) */
#define TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_ALERT              21
#define TLS_CONTENT_HANDSHAKE          22
#define TLS_CONTENT_APPLICATION_DATA   23

#define TLS_RECORD_HEADER_LEN     5
#define TLS_RECORD_TAG_LEN        16
#define TLS_RECORD_MAX_PLAINTEXT  16384   /* 2^14, RFC 8446 §5.1 */

typedef struct {
    uint8_t  key[32];   /* AEAD write key (ChaCha20) */
    uint8_t  iv[12];    /* static write IV */
    uint64_t seq;       /* record sequence number, starts at 0 */
} tls_record_keys;

void tls_record_init(tls_record_keys *k, const uint8_t key[32], const uint8_t iv[12]);

/* Per-record nonce = iv XOR (64-bit big-endian seq, left-padded with zeros to
 * 12 bytes), RFC 8446 §5.3. Exposed so the derivation can be checked in
 * isolation against known values. */
void tls_record_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq);

/* Seal `ptlen` bytes of `plaintext` (inner content type `type`) into a complete
 * TLSCiphertext written to `out`. Returns the total wire length, or -1 on a
 * length/capacity error. Advances seq on success. */
int tls_record_seal(tls_record_keys *k, uint8_t type,
                    const uint8_t *plaintext, size_t ptlen,
                    uint8_t *out, size_t outcap);

/* Open a complete TLSCiphertext (`record`, `reclen` = header + body). On
 * success decrypts into `out`, sets *out_type to the real inner content type,
 * returns the content length (trailing zero padding and the type byte stripped),
 * and advances seq. Returns -1 on a malformed record or authentication failure
 * (including a sequence-number mismatch, since seq feeds the nonce). */
int tls_record_open(tls_record_keys *k,
                    const uint8_t *record, size_t reclen,
                    uint8_t *out, size_t outcap, uint8_t *out_type);
