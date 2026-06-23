/* TLS handshake tracing — semantic events, not strings. v1.
 *
 * The FSM and the record-binding layer emit structured milestones and failures
 * through a per-connection sink (no global state, no printf in the freestanding
 * code). A host test installs a sink that records the event sequence; AuroraOS
 * installs one that prints `[TLS] ...` to the serial log. The first live HTTPS
 * failure should be localizable from the trace alone, e.g.
 *   [TLS] Certificate received / Certificate chain OK / CertificateVerify FAILED
 * rather than a bare "CONNECT FAILED". */
#pragma once
#include <stdint.h>

typedef enum {
    /* milestones, in handshake order */
    TLS_EV_CLIENT_HELLO_SENT = 0,
    TLS_EV_SERVER_HELLO,
    TLS_EV_HANDSHAKE_KEYS,
    TLS_EV_ENCRYPTED_EXTENSIONS,
    TLS_EV_CERTIFICATE,
    TLS_EV_CERT_CHAIN_OK,
    TLS_EV_CERT_VERIFY_OK,
    TLS_EV_PEER_AUTHENTICATED,
    TLS_EV_FINISHED_OK,
    TLS_EV_APP_KEYS,
    TLS_EV_CONNECTED,
    /* failures */
    TLS_EV_FAIL_PROTOCOL,
    TLS_EV_FAIL_CERT,
    TLS_EV_FAIL_AUTH,
    TLS_EV_FAIL_BAD_SIGSCHEME,   /* detail = the SignatureScheme we don't support */
    TLS_EV_FAIL_RECORD           /* record-layer / AEAD failure (conn) */
} tls_event;

/* `detail` carries a value for events that have one (e.g. the signature scheme);
 * it is 0 otherwise. */
typedef void (*tls_trace_sink)(void *ctx, tls_event ev, uint32_t detail);

/* Call the sink if one is installed (no-op otherwise). */
void tls_trace_emit(tls_trace_sink sink, void *ctx, tls_event ev, uint32_t detail);

/* Human-readable name (without the "[TLS] " prefix) for a sink that prints. */
const char *tls_event_name(tls_event ev);
