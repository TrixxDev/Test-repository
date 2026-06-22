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

/* Verify cert's signature under the issuer's SubjectPublicKey bits
 * (issuer_spki_key = the RSAPublicKey DER from the issuer's certificate; for a
 * self-signed certificate, pass cert->spki_key). Returns one of the codes above. */
int x509_verify_signature(const x509_cert *cert,
                          const uint8_t *issuer_spki_key, size_t issuer_spki_key_len);
