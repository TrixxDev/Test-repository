/* TLS 1.3 transcript hash (RFC 8446 §4.4.1) — see transcript.h. */
#include "transcript.h"

void tls_transcript_init(tls_transcript *t)
{
    sha256_init(&t->h);
}

void tls_transcript_update(tls_transcript *t, const void *msg, size_t len)
{
    sha256_update(&t->h, msg, len);
}

void tls_transcript_hash(const tls_transcript *t, uint8_t out[TLS_HASH_LEN])
{
    sha256_ctx snapshot = t->h;     /* copy: finalizing must not consume the stream */
    sha256_final(&snapshot, out);
}
