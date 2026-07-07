/* TLS 1.3 transcript hash (RFC 8446 §4.4.1). A running SHA-256 over the
 * handshake messages in order. The key schedule binds secrets to the transcript
 * via Derive-Secret, so the exact bytes and ordering here are security-critical.
 *
 * The handshake needs the transcript hash at several points (after ServerHello,
 * after server Finished, ...) while still appending later messages, so the hash
 * is taken as a non-destructive snapshot. Part of the tls/ protocol layer. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "sha256.h"

#define TLS_HASH_LEN 32

typedef struct {
    sha256_ctx h;
} tls_transcript;

void tls_transcript_init(tls_transcript *t);

/* Append one complete handshake message (its 4-byte header + body included). */
void tls_transcript_update(tls_transcript *t, const void *msg, size_t len);

/* Snapshot Transcript-Hash(messages so far) without ending the stream. */
void tls_transcript_hash(const tls_transcript *t, uint8_t out[TLS_HASH_LEN]);
