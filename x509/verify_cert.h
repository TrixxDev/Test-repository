/* X.509 signature verification (RFC 5280 §4.1.1.3) — v1.
 *
 * The PKI-policy seam between the parsed certificate and the math: it hashes the
 * TBSCertificate, builds the DER DigestInfo, dispatches on the signature
 * algorithm OID, and calls into crypto/. This is where "TBSCertificate +
 * SignatureAlgorithm + DigestInfo" live (x509/), while crypto/rsa stays a pure
 * primitive that knows none of it.
 *
 * This proves a signature only — it makes NO trust decision (chain, validity
 * window, hostname). That is the trust-store layer on top. RSA + SHA-256 is
 * supported; the dispatcher already has a slot for ECDSA so adding it later needs
 * no restructuring. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "x509.h"

#define X509_VERIFY_OK             0
#define X509_VERIFY_BAD_SIGNATURE -1
#define X509_VERIFY_UNSUPPORTED   -2   /* signature algorithm we don't implement */
#define X509_VERIFY_MALFORMED     -3   /* could not parse the issuer public key */
#define X509_VERIFY_UNTRUSTED     -4   /* no trusted root signed the leaf */

/* validity-window results */
#define X509_VALID_OK        0
#define X509_VALID_NOT_YET  -1   /* now < notBefore */
#define X509_VALID_EXPIRED  -2   /* now > notAfter  */

/* Verify cert's signature under the issuer's SubjectPublicKey bits
 * (issuer_spki_key = the RSAPublicKey DER from the issuer's certificate; for a
 * self-signed certificate, pass cert->spki_key). Returns one of the codes above. */
int x509_verify_signature(const x509_cert *cert,
                          const uint8_t *issuer_spki_key, size_t issuer_spki_key_len);

/* Trust chain (v1: leaf -> trusted root, no intermediates). Returns
 * X509_VERIFY_OK if some root's key validates the leaf's signature, else
 * X509_VERIFY_UNTRUSTED. The array interface is already chain-shaped so
 * intermediate CAs can be added later without an API change. */
int x509_verify_chain(const x509_cert *leaf, const x509_cert *roots, size_t root_count);

/* Validity window: X509_VALID_OK if not_before <= now <= not_after, else
 * X509_VALID_NOT_YET / X509_VALID_EXPIRED. `now` is Unix time. */
int x509_check_validity(const x509_cert *cert, uint64_t now);

/* Hostname match against SubjectAltName dNSName entries (CN is ignored, as modern
 * clients require). Case-insensitive; a leading "*." wildcard matches exactly one
 * left-most label. Returns 0 on a match, -1 otherwise. */
int x509_check_hostname(const x509_cert *cert, const char *hostname);
