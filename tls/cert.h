/* TLS 1.3 Certificate message + PKI glue (RFC 8446 §4.4.2) — v1.
 *
 * The seam where the TLS handshake stops treating the server's certificate as
 * opaque transcript bytes and starts deciding whether to trust it. Two concerns,
 * no cryptography of its own:
 *   1. parse the Certificate wire message into a chain of x509_cert;
 *   2. run the PKI policy on the end-entity certificate — trusted by a root, in
 *      its validity window, matching the hostname.
 *
 * This proves the *certificate* (this key belongs to host X, vouched for by a
 * trusted root). It does NOT prove the peer currently holds the private key —
 * that is CertificateVerify (a later step, with RSA-PSS). v1 is depth 1: the
 * end-entity certificate must be signed directly by a trusted root; intermediate
 * path building comes later behind the same interface. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "x509.h"

#define TLS_MAX_CHAIN 4

typedef struct {
    x509_cert certs[TLS_MAX_CHAIN];   /* certs[0] is the end-entity certificate */
    size_t    count;
} tls_cert_chain;

/* verification results */
#define TLS_CERT_OK            0
#define TLS_CERT_UNTRUSTED    -1
#define TLS_CERT_EXPIRED      -2
#define TLS_CERT_NOT_YET      -3
#define TLS_CERT_BAD_HOSTNAME -4
#define TLS_CERT_MALFORMED    -5

/* Parse a Certificate handshake message (4-byte header + body) into `out`.
 * Certificate slices point into `msg`, which must stay valid while `out` is used.
 * Extra certificates beyond TLS_MAX_CHAIN are skipped (v1 needs only the leaf).
 * Returns 0 on success, -1 if the message or any certificate is malformed. */
int tls_parse_certificate(const uint8_t *msg, size_t len, tls_cert_chain *out);

/* Verify the end-entity certificate: trusted by one of `roots` (depth 1), within
 * its validity window at `now` (Unix time), and matching `hostname` via SAN.
 * A NULL/empty hostname skips the name check. Returns a TLS_CERT_* code. */
int tls_verify_certificate_chain(const tls_cert_chain *chain, const char *hostname,
                                 uint64_t now, const x509_cert *roots, size_t root_count);

/* CertificateVerify results */
#define TLS_CV_OK           0
#define TLS_CV_BAD         -1   /* signature did not verify */
#define TLS_CV_UNSUPPORTED -2   /* signature scheme we don't implement */
#define TLS_CV_MALFORMED   -3   /* could not parse the leaf public key */

/* TLS 1.3 SignatureScheme code points. CertificateVerify dispatches on the value
 * announced in the message (RFC 8446 §4.2.3), and ClientHello advertises the set
 * it can verify (see tls_sigalgs[] in handshake.c). */
#define TLS_SIG_RSA_PKCS1_SHA256        0x0401
#define TLS_SIG_ECDSA_SECP256R1_SHA256  0x0403
#define TLS_SIG_RSA_PSS_RSAE_SHA256     0x0804

/* Verify a server CertificateVerify (RFC 8446 §4.4.3). `transcript_hash` is
 * Transcript-Hash(ClientHello..Certificate); `sig_scheme` is the announced
 * SignatureScheme; `sig` is the raw signature; `leaf_spki_key` is the end-entity
 * certificate's subjectPublicKey bits (RSAPublicKey DER for RSA, the uncompressed
 * point 0x04||X||Y for EC). Builds the signed content (context string + transcript
 * hash) and dispatches on `sig_scheme` — NOT on the certificate key type — to
 * rsa_pss_rsae_sha256 or ecdsa_secp256r1_sha256. A scheme/key mismatch fails in
 * the per-scheme verifier rather than being trusted. Returns a TLS_CV_* code. */
int tls_verify_certificate_verify(const uint8_t transcript_hash[32],
                                  uint16_t sig_scheme,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *leaf_spki_key, size_t leaf_spki_key_len);
