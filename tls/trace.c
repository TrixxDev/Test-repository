/* TLS handshake tracing — see trace.h. */
#include "trace.h"

void tls_trace_emit(tls_trace_sink sink, void *ctx, tls_event ev, uint32_t detail)
{
    if (sink) sink(ctx, ev, detail);
}

const char *tls_event_name(tls_event ev)
{
    switch (ev) {
    case TLS_EV_CLIENT_HELLO_SENT:    return "ClientHello sent";
    case TLS_EV_PSK_OFFERED:          return "PSK offered (session ticket)";
    case TLS_EV_SERVER_HELLO:         return "ServerHello received";
    case TLS_EV_PSK_ACCEPTED:         return "PSK accepted -- resuming";
    case TLS_EV_HANDSHAKE_KEYS:       return "Handshake keys installed";
    case TLS_EV_ENCRYPTED_EXTENSIONS: return "EncryptedExtensions received";
    case TLS_EV_CERTIFICATE:          return "Certificate received";
    case TLS_EV_CERT_CHAIN_OK:        return "Certificate chain OK";
    case TLS_EV_CERT_VERIFY_OK:       return "CertificateVerify OK";
    case TLS_EV_PEER_AUTHENTICATED:   return "Peer authenticated";
    case TLS_EV_FINISHED_OK:          return "Finished OK";
    case TLS_EV_APP_KEYS:             return "Application keys installed";
    case TLS_EV_CONNECTED:            return "CONNECTED";
    case TLS_EV_TICKET_RECEIVED:      return "NewSessionTicket received (cached)";
    case TLS_EV_ALPN_OFFERED:         return "ALPN offered";
    case TLS_EV_ALPN_NEGOTIATED:      return "ALPN negotiated";
    case TLS_EV_FAIL_PROTOCOL:        return "Protocol error";
    case TLS_EV_FAIL_CERT:            return "Certificate validation FAILED";
    case TLS_EV_FAIL_AUTH:            return "CertificateVerify FAILED";
    case TLS_EV_FAIL_BAD_SIGSCHEME:   return "Unsupported SignatureScheme";
    case TLS_EV_FAIL_RECORD:          return "Record decrypt FAILED";
    }
    return "unknown";
}
