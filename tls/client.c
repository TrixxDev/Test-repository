/* TLS 1.3 client handshake state machine — see client.h. */
#include "client.h"
#include "handshake.h"
#include "x25519.h"

static int fail(tls_client *c) { c->state = TLS_ST_ERROR; return -1; }

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
}

int tls_client_start(tls_client *c, uint8_t *out, size_t cap)
{
    if (c->state != TLS_ST_START) return fail(c);
    const char *sni = c->server_name[0] ? c->server_name : 0;
    int n = tls_build_client_hello(out, cap, c->client_random, c->pub, sni);
    if (n < 0) return fail(c);
    tls_transcript_update(&c->transcript, out, (size_t)n);   /* CH enters transcript */
    c->state = TLS_ST_WAIT_SH;
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
        uint8_t spub[32];
        if (tls_parse_server_hello(msg, len, &c->cipher_suite, spub) != 0) return fail(c);
        if (c->cipher_suite != TLS_CIPHER_CHACHA20_POLY1305_SHA256) return fail(c);

        tls_transcript_update(&c->transcript, msg, len);     /* SH enters transcript */

        uint8_t ecdhe[32], hello_hash[32];
        x25519(ecdhe, c->priv, spub);                        /* ECDHE shared secret */
        tls_transcript_hash(&c->transcript, hello_hash);     /* Transcript(CH..SH) */
        tls_key_schedule_derive(&c->ks, ecdhe, hello_hash);
        tls_finished_key(c->client_hs_finished_key, c->ks.client_hs_traffic);
        tls_finished_key(c->server_hs_finished_key, c->ks.server_hs_traffic);

        c->phase = TLS_PHASE_HANDSHAKE;                       /* key switch anchor */
        c->state = TLS_ST_WAIT_EE;
        return 0;
    }
    case TLS_ST_WAIT_EE:
        if (type != TLS_HS_ENCRYPTED_EXTENSIONS) return fail(c);
        tls_transcript_update(&c->transcript, msg, len);     /* not interpreted (v1) */
        c->state = TLS_ST_WAIT_CERT;
        return 0;

    case TLS_ST_WAIT_CERT:
        if (type != TLS_HS_CERTIFICATE) return fail(c);
        tls_transcript_update(&c->transcript, msg, len);     /* not validated (v1) */
        c->state = TLS_ST_WAIT_CV;
        return 0;

    case TLS_ST_WAIT_CV:
        if (type != TLS_HS_CERTIFICATE_VERIFY) return fail(c);
        tls_transcript_update(&c->transcript, msg, len);     /* signature not checked (v1) */
        c->state = TLS_ST_WAIT_FINISHED;
        return 0;

    case TLS_ST_WAIT_FINISHED: {
        if (type != TLS_HS_FINISHED) return fail(c);
        if (len != 4 + 32) return fail(c);

        /* server Finished is verified over the transcript BEFORE it is added */
        uint8_t thash[32];
        tls_transcript_hash(&c->transcript, thash);          /* Transcript(CH..CV) */
        if (tls_check_finished(c->server_hs_finished_key, thash, msg + 4) != 0) return fail(c);

        tls_transcript_update(&c->transcript, msg, len);     /* server Finished added */

        /* app traffic secrets use Transcript(CH..server Finished) */
        uint8_t thash_sf[32];
        tls_transcript_hash(&c->transcript, thash_sf);
        tls_derive_secret(c->client_ap_secret, c->ks.master_secret, "c ap traffic", thash_sf);
        tls_derive_secret(c->server_ap_secret, c->ks.master_secret, "s ap traffic", thash_sf);

        /* client Finished is computed over the same Transcript(CH..server Finished) */
        uint8_t vd[32];
        tls_finished_verify_data(vd, c->client_hs_finished_key, thash_sf);
        int n = build_finished(out, cap, vd);
        if (n < 0) return fail(c);
        tls_transcript_update(&c->transcript, out, (size_t)n);   /* client Finished added */
        *out_len = (size_t)n;

        c->phase = TLS_PHASE_APPLICATION;                    /* key switch anchor */
        c->state = TLS_ST_CONNECTED;
        return 0;
    }
    default:
        return fail(c);
    }
}
