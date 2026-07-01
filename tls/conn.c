/* TLS 1.3 record binding — see conn.h. */
#include "conn.h"
#include "key_schedule.h"
#include "handshake.h"     /* TLS_HS_NEW_SESSION_TICKET, tls_parse_new_session_ticket (15.7) */

/* freestanding byte helpers (no libc, same as the rest of tls/) */
static void cpy(uint8_t *d, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }
/* shift `n` bytes down by `off` (dst < src, so a forward copy is safe) */
static void shift_down(uint8_t *b, size_t n, size_t off) { for (size_t i = 0; i < n; i++) b[i] = b[i + off]; }

/* Install a record epoch from a traffic secret: derive key+iv (HKDF-Expand-Label
 * "key"/"iv") and reset the sequence number to 0 — a fresh epoch (RFC 8446 §5.3).
 * ChaCha20-Poly1305 uses a 32-byte key and 12-byte IV. */
static void install_rx(tls_conn *c, tls_key_phase ph)
{
    const uint8_t *secret = (ph == TLS_PHASE_HANDSHAKE) ? c->fsm.ks.server_hs_traffic
                                                        : c->fsm.server_ap_secret;
    uint8_t key[32], iv[12];
    tls_traffic_keys(secret, key, 32, iv, 12);
    tls_record_init(&c->rx, key, iv);
    c->rx_phase = ph;
}

static void install_tx(tls_conn *c, tls_key_phase ph)
{
    const uint8_t *secret = (ph == TLS_PHASE_HANDSHAKE) ? c->fsm.ks.client_hs_traffic
                                                        : c->fsm.client_ap_secret;
    uint8_t key[32], iv[12];
    tls_traffic_keys(secret, key, 32, iv, 12);
    tls_record_init(&c->tx, key, iv);
    c->tx_phase = ph;
}

void tls_conn_init(tls_conn *c, const char *server_name,
                   const uint8_t ephemeral_priv[32], const uint8_t client_random[32])
{
    tls_client_init(&c->fsm, server_name, ephemeral_priv, client_random);
    c->rx_phase = TLS_PHASE_EARLY;
    c->tx_phase = TLS_PHASE_EARLY;
    c->hs_len = 0;
    c->has_pending_ticket = 0;
}

int tls_conn_take_ticket(tls_conn *c, tls_session_ticket *out)
{
    if (!c->has_pending_ticket) return 0;
    *out = c->pending_ticket;
    c->has_pending_ticket = 0;
    return 1;
}

/* Wrap a body in a plaintext TLS record: type | 0x0303 | uint16(len) | body. */
static int plaintext_record(uint8_t *out, size_t outcap, uint8_t type,
                            const uint8_t *body, size_t blen)
{
    if (blen > 0xffff || TLS_RECORD_HEADER_LEN + blen > outcap) return TLS_CONN_ERR_CAPACITY;
    out[0] = type; out[1] = 0x03; out[2] = 0x03;
    out[3] = (uint8_t)(blen >> 8); out[4] = (uint8_t)(blen & 0xff);
    cpy(out + TLS_RECORD_HEADER_LEN, body, blen);
    return (int)(TLS_RECORD_HEADER_LEN + blen);
}

int tls_conn_start(tls_conn *c, uint8_t *out, size_t outcap)
{
    uint8_t ch[1024];
    int chlen = tls_client_start(&c->fsm, ch, sizeof ch);
    if (chlen < 0) return TLS_CONN_ERR_PROTOCOL;
    /* ClientHello is sent in the clear (EARLY epoch). */
    return plaintext_record(out, outcap, TLS_CONTENT_HANDSHAKE, ch, (size_t)chlen);
}

/* Drain the reassembly buffer: hand the FSM one complete handshake message at a
 * time, switch epochs at the phase anchors, and seal any FSM-emitted message
 * (the client Finished) under the current tx epoch. */
static int run_splitter(tls_conn *c, uint8_t *out, size_t outcap, size_t *out_len)
{
    size_t off = 0;
    int ret = TLS_CONN_OK;

    while (c->hs_len - off >= 4) {
        const uint8_t *m = c->hs_buf + off;
        size_t mlen = 4 + (((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3]);
        if (mlen > sizeof c->hs_buf) { ret = TLS_CONN_ERR_CAPACITY; break; } /* can't ever buffer */
        if (c->hs_len - off < mlen) break;                                    /* fragment: need more */

        tls_key_phase before = c->fsm.phase;
        uint8_t emitted[64]; size_t emitted_len = 0;
        int rc = tls_client_recv_handshake(&c->fsm, m, mlen, emitted, sizeof emitted, &emitted_len);
        if (rc != 0) { ret = TLS_CONN_ERR_PROTOCOL; off += mlen; break; }     /* FSM already in ERROR */

        /* anchor 1: ServerHello took us EARLY -> HANDSHAKE; install handshake keys */
        if (before == TLS_PHASE_EARLY && c->fsm.phase == TLS_PHASE_HANDSHAKE) {
            install_rx(c, TLS_PHASE_HANDSHAKE);
            install_tx(c, TLS_PHASE_HANDSHAKE);
        }

        /* the client Finished is sealed under the *current* (handshake) tx epoch,
         * before we move tx on to application keys */
        if (emitted_len > 0) {
            int rl = tls_record_seal(&c->tx, TLS_CONTENT_HANDSHAKE, emitted, emitted_len,
                                     out + *out_len, outcap - *out_len);
            if (rl < 0) { ret = TLS_CONN_ERR_CAPACITY; off += mlen; break; }
            *out_len += (size_t)rl;
        }

        /* anchor 2: server Finished took us HANDSHAKE -> APPLICATION; install app keys */
        if (before == TLS_PHASE_HANDSHAKE && c->fsm.phase == TLS_PHASE_APPLICATION) {
            install_rx(c, TLS_PHASE_APPLICATION);
            install_tx(c, TLS_PHASE_APPLICATION);
        }

        off += mlen;
    }

    if (off > 0) {                       /* drop consumed messages, keep any partial */
        c->hs_len -= off;
        shift_down(c->hs_buf, c->hs_len, off);
    }
    return ret;
}

int tls_conn_recv_record(tls_conn *c, const uint8_t *record, size_t reclen,
                         uint8_t *out, size_t outcap, size_t *out_len)
{
    *out_len = 0;
    if (reclen < TLS_RECORD_HEADER_LEN) return TLS_CONN_ERR_RECORD;

    /* ChangeCipherSpec is legacy middlebox-compat noise in TLS 1.3: ignore it. */
    if (record[0] == TLS_CONTENT_CHANGE_CIPHER_SPEC) return TLS_CONN_OK;

    if (c->rx_phase == TLS_PHASE_EARLY) {
        /* not yet keyed: expect a plaintext handshake record (ServerHello) */
        if (record[0] != TLS_CONTENT_HANDSHAKE) return TLS_CONN_ERR_RECORD;
        size_t body = ((size_t)record[3] << 8) | record[4];
        if (reclen != TLS_RECORD_HEADER_LEN + body) return TLS_CONN_ERR_RECORD;
        if (body > sizeof c->hs_buf - c->hs_len) return TLS_CONN_ERR_CAPACITY;
        cpy(c->hs_buf + c->hs_len, record + TLS_RECORD_HEADER_LEN, body);
        c->hs_len += body;
    } else {
        /* keyed epoch: the wire record is application_data; open it. An AEAD
         * failure is a transport error that must NOT touch the FSM (invariant). */
        if (record[0] != TLS_CONTENT_APPLICATION_DATA) return TLS_CONN_ERR_RECORD;
        size_t enc_len = ((size_t)record[3] << 8) | record[4];
        if (enc_len < TLS_RECORD_TAG_LEN + 1) return TLS_CONN_ERR_RECORD;
        size_t inner_max = enc_len - TLS_RECORD_TAG_LEN;       /* plaintext upper bound */
        if (inner_max > sizeof c->hs_buf - c->hs_len) return TLS_CONN_ERR_CAPACITY;

        uint8_t inner_type;
        int n = tls_record_open(&c->rx, record, reclen, c->hs_buf + c->hs_len, inner_max, &inner_type);
        if (n < 0) {                                           /* FSM untouched */
            tls_trace_emit(c->fsm.trace, c->fsm.trace_ctx, TLS_EV_FAIL_RECORD, 0);
            return TLS_CONN_ERR_RECORD;
        }
        if (inner_type == TLS_CONTENT_ALERT) return TLS_CONN_ERR_ALERT;
        if (inner_type != TLS_CONTENT_HANDSHAKE) return TLS_CONN_ERR_RECORD;
        c->hs_len += (size_t)n;
    }

    return run_splitter(c, out, outcap, out_len);
}

int tls_conn_send_app(tls_conn *c, const uint8_t *data, size_t len,
                      uint8_t *out, size_t outcap)
{
    if (c->fsm.state != TLS_ST_CONNECTED || c->tx_phase != TLS_PHASE_APPLICATION)
        return TLS_CONN_ERR_PROTOCOL;
    int rl = tls_record_seal(&c->tx, TLS_CONTENT_APPLICATION_DATA, data, len, out, outcap);
    return rl < 0 ? TLS_CONN_ERR_CAPACITY : rl;
}

int tls_conn_recv_app(tls_conn *c, const uint8_t *record, size_t reclen,
                      uint8_t *out, size_t outcap, size_t *out_len)
{
    *out_len = 0;
    if (c->fsm.state != TLS_ST_CONNECTED || c->rx_phase != TLS_PHASE_APPLICATION)
        return TLS_CONN_ERR_PROTOCOL;
    if (reclen < TLS_RECORD_HEADER_LEN) return TLS_CONN_ERR_RECORD;
    if (record[0] == TLS_CONTENT_CHANGE_CIPHER_SPEC) return TLS_CONN_OK;
    if (record[0] != TLS_CONTENT_APPLICATION_DATA) return TLS_CONN_ERR_RECORD;

    uint8_t inner_type;
    int n = tls_record_open(&c->rx, record, reclen, out, outcap, &inner_type);
    if (n < 0) return TLS_CONN_ERR_RECORD;
    if (inner_type == TLS_CONTENT_ALERT) return TLS_CONN_ERR_ALERT;
    if (inner_type == TLS_CONTENT_HANDSHAKE) {
        /* A post-handshake handshake message: only NewSessionTicket exists in
         * practice (15.7). Parse it if we can (need the resumption master
         * secret, which only exists once CONNECTED -- always true here); any
         * failure (malformed, oversized, not actually a ticket) is silently
         * ignored, same as the pre-15.7 behavior, since a missed ticket just
         * means the next connection does a full handshake instead. */
        if ((size_t)n >= 4 && out[0] == TLS_HS_NEW_SESSION_TICKET && c->fsm.has_resumption_secret) {
            uint8_t nonce[255]; size_t nonce_len = 0;
            tls_session_ticket t;
            t.obtained_ms = 0;   /* tls/ has no clock; the caller must set this
                                  * after tls_conn_take_ticket() returns, before
                                  * offering the ticket on a future connection */
            if (tls_parse_new_session_ticket(out, (size_t)n, &t, nonce, sizeof nonce, &nonce_len) == 0) {
                tls_derive_ticket_psk(t.psk, c->fsm.resumption_master_secret, nonce, nonce_len);
                c->pending_ticket = t;
                c->has_pending_ticket = 1;
                tls_trace_emit(c->fsm.trace, c->fsm.trace_ctx, TLS_EV_TICKET_RECEIVED, 0);
            }
        }
        return TLS_CONN_OK;
    }
    if (inner_type != TLS_CONTENT_APPLICATION_DATA) return TLS_CONN_ERR_RECORD;

    *out_len = (size_t)n;
    return TLS_CONN_OK;
}
