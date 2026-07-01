/* TLS 1.3 client handshake state machine — see client.h. */
#include "client.h"
#include "handshake.h"
#include "x25519.h"

static void emit(tls_client *c, tls_event ev, uint32_t detail)
{
    tls_trace_emit(c->trace, c->trace_ctx, ev, detail);
}

static int fail(tls_client *c)      { c->state = TLS_ST_ERROR; c->error = TLS_ERR_PROTOCOL; emit(c, TLS_EV_FAIL_PROTOCOL, 0); return -1; }
static int fail_cert(tls_client *c) { c->state = TLS_ST_ERROR; c->error = TLS_ERR_CERT;     emit(c, TLS_EV_FAIL_CERT, 0);     return -1; }
static int fail_auth(tls_client *c) { c->state = TLS_ST_ERROR; c->error = TLS_ERR_AUTH;     emit(c, TLS_EV_FAIL_AUTH, 0);     return -1; }

void tls_client_init(tls_client *c, const char *server_name,
                     const uint8_t ephemeral_priv[32],
                     const uint8_t client_random[32])
{
    c->state = TLS_ST_START;
    c->phase = TLS_PHASE_EARLY;
    tls_transcript_init(&c->transcript);

    for (int i = 0; i < 32; i++) { c->priv[i] = ephemeral_priv[i]; c->client_random[i] = client_random[i]; }
    x25519_base(c->pub, c->priv);

    size_t i = 0;
    if (server_name) { for (; server_name[i] && i < sizeof(c->server_name) - 1; i++) c->server_name[i] = server_name[i]; }
    c->server_name[i] = 0;
    c->cipher_suite = 0;
    c->cv_scheme = 0;

    c->roots = 0;            /* trust off until tls_client_set_trust */
    c->root_count = 0;
    c->now = 0;
    c->leaf_spki_len = 0;
    c->peer_authenticated = 0;
    c->error = TLS_ERR_NONE;
    c->cert_reason = 0;

    c->offered_resume = 0;   /* full handshake until tls_client_offer_psk */
    c->offer_now_ms = 0;
    c->psk_accepted = 0;
    c->has_resumption_secret = 0;

    c->trace = 0;
    c->trace_ctx = 0;
}

void tls_client_offer_psk(tls_client *c, const tls_session_ticket *resume, uint64_t now_ms)
{
    c->offered_resume = resume;
    c->offer_now_ms = now_ms;
    if (resume) {
        tls_derive_early_secret(c->psk_early_secret, resume->psk, sizeof resume->psk);
        tls_derive_binder_key(c->binder_key, c->psk_early_secret);
    }
}

void tls_client_set_trust(tls_client *c, const x509_cert *roots, size_t root_count,
                          uint64_t now)
{
    c->roots = roots;
    c->root_count = root_count;
    c->now = now;
}

void tls_client_set_trace(tls_client *c, tls_trace_sink fn, void *ctx)
{
    c->trace = fn;
    c->trace_ctx = ctx;
}

int tls_client_start(tls_client *c, uint8_t *out, size_t cap)
{
    if (c->state != TLS_ST_START) return fail(c);
    const char *sni = c->server_name[0] ? c->server_name : 0;
    int n = tls_build_client_hello(out, cap, c->client_random, c->pub, sni,
                                   c->offered_resume, c->offer_now_ms, c->binder_key);
    if (n < 0) return fail(c);
    tls_transcript_update(&c->transcript, out, (size_t)n);   /* CH enters transcript */
    c->state = TLS_ST_WAIT_SH;
    emit(c, TLS_EV_CLIENT_HELLO_SENT, 0);
    if (c->offered_resume) emit(c, TLS_EV_PSK_OFFERED, 0);
    return n;
}

/* Build a Finished handshake message (type + 24-bit len(32) + verify_data). */
static int build_finished(uint8_t *out, size_t cap, const uint8_t vd[32])
{
    if (cap < 4 + 32) return -1;
    out[0] = TLS_HS_FINISHED; out[1] = 0; out[2] = 0; out[3] = 32;
    for (int i = 0; i < 32; i++) out[4 + i] = vd[i];
    return 4 + 32;
}

int tls_client_recv_handshake(tls_client *c, const uint8_t *msg, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len)
{
    *out_len = 0;
    if (len < 4) return fail(c);
    uint8_t type = msg[0];

    switch (c->state) {
    case TLS_ST_WAIT_SH: {
        if (type != TLS_HS_SERVER_HELLO) return fail(c);
        uint8_t spub[32]; int psk_selected = 0;
        if (tls_parse_server_hello(msg, len, &c->cipher_suite, spub, &psk_selected) != 0) return fail(c);
        if (c->cipher_suite != TLS_CIPHER_CHACHA20_POLY1305_SHA256) return fail(c);

        tls_transcript_update(&c->transcript, msg, len);     /* SH enters transcript */
        emit(c, TLS_EV_SERVER_HELLO, 0);

        /* RFC 8446 §4.1.4: only use the PSK-derived early secret if the
         * server actually selected it; otherwise this is silently a full
         * handshake and the early secret reverts to PSK=0, same as always. */
        c->psk_accepted = c->offered_resume && psk_selected;
        uint8_t early_secret[32];
        if (c->psk_accepted) {
            for (int i = 0; i < 32; i++) early_secret[i] = c->psk_early_secret[i];
            emit(c, TLS_EV_PSK_ACCEPTED, 0);
        } else {
            tls_derive_early_secret(early_secret, 0, 0);
        }

        uint8_t ecdhe[32], hello_hash[32];
        x25519(ecdhe, c->priv, spub);                        /* ECDHE shared secret */
        tls_transcript_hash(&c->transcript, hello_hash);     /* Transcript(CH..SH) */
        tls_key_schedule_derive_from_early(&c->ks, early_secret, ecdhe, hello_hash);
        tls_finished_key(c->client_hs_finished_key, c->ks.client_hs_traffic);
        tls_finished_key(c->server_hs_finished_key, c->ks.server_hs_traffic);

        c->phase = TLS_PHASE_HANDSHAKE;                       /* key switch anchor */
        c->state = TLS_ST_WAIT_EE;
        emit(c, TLS_EV_HANDSHAKE_KEYS, 0);
        return 0;
    }
    case TLS_ST_WAIT_EE:
        if (type != TLS_HS_ENCRYPTED_EXTENSIONS) return fail(c);
        tls_transcript_update(&c->transcript, msg, len);     /* not interpreted (v1) */
        /* A resumed (PSK-accepted) handshake skips Certificate/CertificateVerify
         * entirely -- PSK possession is the authentication (RFC 8446 §2.2). */
        c->state = c->psk_accepted ? TLS_ST_WAIT_FINISHED : TLS_ST_WAIT_CERT;
        emit(c, TLS_EV_ENCRYPTED_EXTENSIONS, 0);
        return 0;

    case TLS_ST_WAIT_CERT:
        if (type != TLS_HS_CERTIFICATE) return fail(c);
        tls_transcript_update(&c->transcript, msg, len);     /* always enters the transcript */
        emit(c, TLS_EV_CERTIFICATE, 0);
        if (c->roots) {                                      /* trust store installed: validate */
            if (tls_parse_certificate(msg, len, &c->certs) != 0) { c->cert_reason = TLS_CERT_MALFORMED; return fail_cert(c); }
            int cr = tls_verify_certificate_chain(&c->certs, c->server_name, c->now,
                                                  c->roots, c->root_count);
            if (cr != TLS_CERT_OK) { c->cert_reason = cr; return fail_cert(c); }
            /* keep the leaf public key for CertificateVerify: the parsed slices
             * point into `msg`, which is gone by the next message */
            const x509_slice *k = &c->certs.certs[0].spki_key;
            if (k->len > sizeof c->leaf_spki) return fail_cert(c);
            for (size_t i = 0; i < k->len; i++) c->leaf_spki[i] = k->p[i];
            c->leaf_spki_len = k->len;
            emit(c, TLS_EV_CERT_CHAIN_OK, 0);
        }
        c->state = TLS_ST_WAIT_CV;
        return 0;

    case TLS_ST_WAIT_CV:
        if (type != TLS_HS_CERTIFICATE_VERIFY) return fail(c);
        if (c->roots) {
            /* CertificateVerify signs Transcript(CH..Certificate): snapshot the
             * transcript BEFORE appending this message (RFC 8446 §4.4.3). */
            uint8_t th[32];
            tls_transcript_hash(&c->transcript, th);
            if (len < 8) return fail(c);
            uint16_t scheme = (uint16_t)((msg[4] << 8) | msg[5]);
            size_t   siglen = (size_t)((msg[6] << 8) | msg[7]);
            if (8 + siglen != len) return fail(c);
            int rc = tls_verify_certificate_verify(th, scheme, msg + 8, siglen,
                                                   c->leaf_spki, c->leaf_spki_len);
            if (rc != TLS_CV_OK) {
                if (rc == TLS_CV_UNSUPPORTED) emit(c, TLS_EV_FAIL_BAD_SIGSCHEME, scheme);
                return fail_auth(c);
            }
            c->cv_scheme = scheme;                           /* remember for diagnostics */
            emit(c, TLS_EV_CERT_VERIFY_OK, 0);
            c->peer_authenticated = 1;                       /* server proved key ownership */
            emit(c, TLS_EV_PEER_AUTHENTICATED, 0);
        }
        tls_transcript_update(&c->transcript, msg, len);     /* CV enters the transcript after */
        c->state = TLS_ST_WAIT_FINISHED;
        return 0;

    case TLS_ST_WAIT_FINISHED: {
        if (type != TLS_HS_FINISHED) return fail(c);
        if (len != 4 + 32) return fail(c);

        /* server Finished is verified over the transcript BEFORE it is added */
        uint8_t thash[32];
        tls_transcript_hash(&c->transcript, thash);          /* Transcript(CH..CV, or CH..EE if resumed) */
        if (tls_check_finished(c->server_hs_finished_key, thash, msg + 4) != 0) return fail(c);
        emit(c, TLS_EV_FINISHED_OK, 0);
        if (c->psk_accepted) {
            /* No CertificateVerify in a resumed handshake (RFC 8446 §2.2) --
             * a valid Finished IS the proof the server holds the PSK. */
            c->peer_authenticated = 1;
            emit(c, TLS_EV_PEER_AUTHENTICATED, 0);
        }

        tls_transcript_update(&c->transcript, msg, len);     /* server Finished added */

        /* app traffic secrets use Transcript(CH..server Finished) */
        uint8_t thash_sf[32];
        tls_transcript_hash(&c->transcript, thash_sf);
        tls_derive_secret(c->client_ap_secret, c->ks.master_secret, "c ap traffic", thash_sf);
        tls_derive_secret(c->server_ap_secret, c->ks.master_secret, "s ap traffic", thash_sf);
        emit(c, TLS_EV_APP_KEYS, 0);

        /* client Finished is computed over the same Transcript(CH..server Finished) */
        uint8_t vd[32];
        tls_finished_verify_data(vd, c->client_hs_finished_key, thash_sf);
        int n = build_finished(out, cap, vd);
        if (n < 0) return fail(c);
        tls_transcript_update(&c->transcript, out, (size_t)n);   /* client Finished added */
        *out_len = (size_t)n;

        /* resumption_master_secret, for a future NewSessionTicket's PSK
         * (RFC 8446 §7.1: Transcript(CH..client Finished), i.e. now). */
        uint8_t thash_cf[32];
        tls_transcript_hash(&c->transcript, thash_cf);
        tls_derive_resumption_master_secret(c->resumption_master_secret, c->ks.master_secret, thash_cf);
        c->has_resumption_secret = 1;

        c->phase = TLS_PHASE_APPLICATION;                    /* key switch anchor */
        c->state = TLS_ST_CONNECTED;
        emit(c, TLS_EV_CONNECTED, 0);
        return 0;
    }
    default:
        return fail(c);
    }
}
