/* TLS 1.3 handshake message layer (RFC 8446 §4) — see handshake.h. */
#include "handshake.h"
#include "key_schedule.h"
#include "hmac_sha256.h"
#include "sha256.h"        /* the binder's prefix hash (Phase 15.7) */
#include "cert.h"          /* TLS_SIG_* SignatureScheme code points */

/* SignatureScheme values offered in ClientHello.signature_algorithms, in
 * descending preference. This is the single source of truth for what the client
 * advertises; adding a scheme (e.g. ed25519) is one line here, and it must also
 * be handled in tls_verify_certificate_verify. */
static const uint16_t tls_sigalgs[] = {
    TLS_SIG_ECDSA_SECP384R1_SHA384,
    TLS_SIG_ECDSA_SECP256R1_SHA256,
    TLS_SIG_RSA_PSS_RSAE_SHA256,
    TLS_SIG_RSA_PKCS1_SHA256,
};

/* ------------------------------------------------------------------ */
/* tiny append-only writer with length back-patching                  */
/* ------------------------------------------------------------------ */
typedef struct { uint8_t *p; size_t cap, len; int err; } wbuf;

static void w_u8(wbuf *b, uint8_t v)  { if (b->len + 1 > b->cap) { b->err = 1; return; } b->p[b->len++] = v; }
static void w_u16(wbuf *b, uint16_t v){ w_u8(b, (uint8_t)(v >> 8)); w_u8(b, (uint8_t)v); }
static void w_u24(wbuf *b, uint32_t v){ w_u8(b, (uint8_t)(v >> 16)); w_u8(b, (uint8_t)(v >> 8)); w_u8(b, (uint8_t)v); }
static void w_u32(wbuf *b, uint32_t v){ w_u8(b, (uint8_t)(v >> 24)); w_u8(b, (uint8_t)(v >> 16)); w_u8(b, (uint8_t)(v >> 8)); w_u8(b, (uint8_t)v); }
static void w_bytes(wbuf *b, const uint8_t *d, size_t n) { for (size_t i = 0; i < n; i++) w_u8(b, d[i]); }

/* reserve a 1-byte (or 2-/3-byte) length to be filled in by w_close* */
static size_t w_open8(wbuf *b)  { size_t at = b->len; w_u8(b, 0); return at; }
static void   w_close8(wbuf *b, size_t at) { b->p[at] = (uint8_t)(b->len - at - 1); }
static size_t w_open16(wbuf *b) { size_t at = b->len; w_u16(b, 0); return at; }
static void   w_close16(wbuf *b, size_t at) { size_t n = b->len - at - 2; b->p[at] = (uint8_t)(n >> 8); b->p[at+1] = (uint8_t)n; }
static size_t w_open24(wbuf *b) { size_t at = b->len; w_u24(b, 0); return at; }
static void   w_close24(wbuf *b, size_t at) { size_t n = b->len - at - 3; b->p[at] = (uint8_t)(n >> 16); b->p[at+1] = (uint8_t)(n >> 8); b->p[at+2] = (uint8_t)n; }

int tls_build_client_hello(uint8_t *out, size_t cap,
                           const uint8_t random[32],
                           const uint8_t x25519_pub[32],
                           const char *server_name,
                           const char **alpn_protocols, size_t alpn_count,
                           const tls_session_ticket *resume,
                           uint64_t now_ms,
                           const uint8_t binder_key[32])
{
    wbuf b = { out, cap, 0, 0 };

    w_u8(&b, TLS_HS_CLIENT_HELLO);
    size_t hs = w_open24(&b);                    /* handshake length */

    w_u16(&b, 0x0303);                           /* legacy_version */
    w_bytes(&b, random, 32);                      /* random */

    w_u8(&b, 32);                                 /* legacy_session_id<0..32> */
    for (int i = 0; i < 32; i++) w_u8(&b, 0);     /* (32 zero bytes, compat) */

    w_u16(&b, 2);                                 /* cipher_suites length */
    w_u16(&b, TLS_CIPHER_CHACHA20_POLY1305_SHA256);

    w_u8(&b, 1); w_u8(&b, 0);                      /* legacy_compression_methods = {null} */

    size_t exts = w_open16(&b);                   /* extensions */

    /* supported_versions (43): list of one, TLS 1.3 */
    w_u16(&b, 43);
    { size_t e = w_open16(&b); w_u8(&b, 2); w_u16(&b, 0x0304); w_close16(&b, e); }

    /* supported_groups (10): x25519 */
    w_u16(&b, 10);
    { size_t e = w_open16(&b); w_u16(&b, 2); w_u16(&b, TLS_GROUP_X25519); w_close16(&b, e); }

    /* signature_algorithms (13): the schemes we can verify (see tls_sigalgs[]) */
    w_u16(&b, 13);
    { size_t e = w_open16(&b); size_t l = w_open16(&b);
      for (size_t i = 0; i < sizeof tls_sigalgs / sizeof tls_sigalgs[0]; i++)
          w_u16(&b, tls_sigalgs[i]);
      w_close16(&b, l); w_close16(&b, e); }

    /* key_share (51): one entry, x25519 */
    w_u16(&b, 51);
    { size_t e = w_open16(&b); size_t l = w_open16(&b);
      w_u16(&b, TLS_GROUP_X25519); w_u16(&b, 32); w_bytes(&b, x25519_pub, 32);
      w_close16(&b, l); w_close16(&b, e); }

    /* server_name (0): SNI host_name, optional */
    if (server_name) {
        size_t hlen = 0; while (server_name[hlen]) hlen++;
        w_u16(&b, 0);
        { size_t e = w_open16(&b); size_t l = w_open16(&b);
          w_u8(&b, 0);                            /* name_type = host_name */
          w_u16(&b, (uint16_t)hlen);
          w_bytes(&b, (const uint8_t *)server_name, hlen);
          w_close16(&b, l); w_close16(&b, e); }
    }

    /* application_layer_protocol_negotiation (16, RFC 7301, Phase 17.0):
     * ProtocolNameList of uint8-length-prefixed names, in preference order.
     * Optional -- omitted entirely (byte-identical to the pre-17.0 shape)
     * unless the caller offered at least one protocol. Must come before the
     * pre_shared_key block below, which has to stay last. */
    if (alpn_protocols && alpn_count > 0) {
        w_u16(&b, 16);
        { size_t e = w_open16(&b); size_t l = w_open16(&b);
          for (size_t ai = 0; ai < alpn_count; ai++) {
              size_t plen = 0; while (alpn_protocols[ai][plen]) plen++;
              w_u8(&b, (uint8_t)plen);
              w_bytes(&b, (const uint8_t *)alpn_protocols[ai], plen);
          }
          w_close16(&b, l); w_close16(&b, e); }
    }

    /* Resumption (Phase 15.7, RFC 8446 §4.2.11): pre_shared_key MUST be the
     * last extension, so both go here, after everything above. */
    size_t binders_at = 0, hmac_at = 0;
    if (resume) {
        /* psk_key_exchange_modes (45): psk_dhe_ke (1) only -- we always pair
         * the PSK with a fresh ECDHE exchange, never pure-PSK, so a resumed
         * connection keeps forward secrecy. */
        w_u16(&b, 45);
        { size_t e = w_open16(&b); size_t l = w_open8(&b); w_u8(&b, 1); w_close8(&b, l); w_close16(&b, e); }

        /* pre_shared_key (41): one offered identity (our cached ticket) and
         * one binder. The binder itself is a placeholder here -- it can only
         * be computed once every length field before it is fixed, which
         * requires this whole extension (including the binders list) to
         * already be the right size. It's patched in below. */
        w_u16(&b, 41);
        size_t e = w_open16(&b);
        size_t ids = w_open16(&b);
        { size_t idlen = w_open16(&b); w_bytes(&b, resume->ticket, resume->ticket_len); w_close16(&b, idlen); }
        uint32_t obfuscated_age = (uint32_t)(now_ms - resume->obtained_ms) + resume->age_add;
        w_u32(&b, obfuscated_age);
        w_close16(&b, ids);

        binders_at = b.len;                       /* everything before here enters the binder hash */
        size_t binders = w_open16(&b);
        w_u8(&b, 32);
        hmac_at = b.len;
        for (int i = 0; i < 32; i++) w_u8(&b, 0);  /* placeholder HMAC, patched below */
        w_close16(&b, binders);
        w_close16(&b, e);
    }

    w_close16(&b, exts);
    w_close24(&b, hs);

    if (b.err) return -1;

    if (resume) {
        /* The binder covers the ClientHello "up to and including the
         * PreSharedKeyExtension.identities field but excluding the binders
         * list" (RFC 8446 §4.2.11.2) -- exactly the bytes before binders_at,
         * now that every length field up to there is already final. */
        uint8_t prefix_hash[32];
        sha256(out, binders_at, prefix_hash);
        uint8_t finished_key[32], binder[32];
        tls_finished_key(finished_key, binder_key);
        tls_finished_verify_data(binder, finished_key, prefix_hash);
        for (int i = 0; i < 32; i++) out[hmac_at + i] = binder[i];
    }

    return (int)b.len;
}

/* ------------------------------------------------------------------ */
/* ServerHello parser (bounds-checked)                                */
/* ------------------------------------------------------------------ */
int tls_parse_server_hello(const uint8_t *msg, size_t len,
                           uint16_t *cipher_suite,
                           uint8_t server_x25519_pub[32],
                           int *psk_selected)
{
    size_t i = 0;
    #define NEED(n) do { if (i + (n) > len) return -1; } while (0)
    if (psk_selected) *psk_selected = 0;

    NEED(4);
    if (msg[0] != TLS_HS_SERVER_HELLO) return -1;
    size_t body = ((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3];
    i = 4;
    if (i + body != len) return -1;

    NEED(2); i += 2;                              /* legacy_version */
    NEED(32); i += 32;                            /* random */

    NEED(1); { size_t sid = msg[i++]; NEED(sid); i += sid; }   /* session_id_echo */

    NEED(2); *cipher_suite = (uint16_t)((msg[i] << 8) | msg[i+1]); i += 2;
    NEED(1); i += 1;                              /* legacy_compression_method */

    NEED(2); size_t extlen = ((size_t)msg[i] << 8) | msg[i+1]; i += 2;
    NEED(extlen);
    size_t end = i + extlen;

    int have_key_share = 0;
    while (i + 4 <= end) {
        uint16_t etype = (uint16_t)((msg[i] << 8) | msg[i+1]);
        size_t elen = ((size_t)msg[i+2] << 8) | msg[i+3];
        i += 4;
        if (i + elen > end) return -1;

        if (etype == 51) {                        /* key_share: KeyShareEntry */
            if (elen < 4) return -1;
            uint16_t group = (uint16_t)((msg[i] << 8) | msg[i+1]);
            size_t klen = ((size_t)msg[i+2] << 8) | msg[i+3];
            if (4 + klen > elen) return -1;
            if (group == TLS_GROUP_X25519) {
                if (klen != 32) return -1;
                for (int k = 0; k < 32; k++) server_x25519_pub[k] = msg[i + 4 + k];
                have_key_share = 1;
            }
        } else if (etype == 41) {                 /* pre_shared_key: just selected_identity (uint16) */
            if (elen != 2) return -1;
            /* We only ever offer one identity (index 0), so presence alone --
             * regardless of the index value -- means our PSK was selected. */
            if (psk_selected) *psk_selected = 1;
        }
        i += elen;
    }
    #undef NEED
    return have_key_share ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* EncryptedExtensions parser (bounds-checked; ALPN -- Phase 17.0)    */
/* ------------------------------------------------------------------ */
int tls_parse_encrypted_extensions(const uint8_t *msg, size_t len,
                                   char *alpn_out, size_t alpn_out_cap,
                                   int *alpn_negotiated)
{
    size_t i = 0;
    #define NEED(n) do { if (i + (n) > len) return -1; } while (0)
    if (alpn_negotiated) *alpn_negotiated = 0;
    if (alpn_out && alpn_out_cap > 0) alpn_out[0] = 0;

    NEED(4);
    if (msg[0] != TLS_HS_ENCRYPTED_EXTENSIONS) return -1;
    size_t body = ((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3];
    i = 4;
    if (i + body != len) return -1;

    NEED(2); size_t extlen = ((size_t)msg[i] << 8) | msg[i+1]; i += 2;
    NEED(extlen);
    size_t end = i + extlen;

    while (i + 4 <= end) {
        uint16_t etype = (uint16_t)((msg[i] << 8) | msg[i+1]);
        size_t elen = ((size_t)msg[i+2] << 8) | msg[i+3];
        i += 4;
        if (i + elen > end) return -1;

        if (etype == 16) {                        /* ALPN: ProtocolNameList */
            /* RFC 7301 §3.2: the server's response carries exactly one
             * protocol name (its selection); a uint16 list length followed
             * by one uint8-length-prefixed name. */
            if (elen < 3) return -1;
            size_t list_len = ((size_t)msg[i] << 8) | msg[i+1];
            if (2 + list_len > elen || list_len < 1) return -1;
            size_t p = i + 2;
            size_t plen = msg[p];
            if (1 + plen > list_len) return -1;
            if (alpn_out && alpn_out_cap > 0) {
                size_t n = plen < alpn_out_cap - 1 ? plen : alpn_out_cap - 1;
                for (size_t k = 0; k < n; k++) alpn_out[k] = (char)msg[p + 1 + k];
                alpn_out[n] = 0;
            }
            if (alpn_negotiated) *alpn_negotiated = 1;
        }
        i += elen;
    }
    #undef NEED
    return 0;
}

/* ------------------------------------------------------------------ */
/* NewSessionTicket (RFC 8446 §4.6.1)                                 */
/* ------------------------------------------------------------------ */
int tls_parse_new_session_ticket(const uint8_t *msg, size_t len,
                                 tls_session_ticket *out,
                                 uint8_t *nonce, size_t nonce_cap, size_t *nonce_len)
{
    size_t i = 0;
    #define NEED(n) do { if (i + (n) > len) return -1; } while (0)

    NEED(4);
    if (msg[0] != TLS_HS_NEW_SESSION_TICKET) return -1;
    size_t body = ((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3];
    i = 4;
    if (i + body != len) return -1;

    NEED(4);
    out->lifetime_secs = ((uint32_t)msg[i] << 24) | ((uint32_t)msg[i+1] << 16) |
                         ((uint32_t)msg[i+2] << 8) | (uint32_t)msg[i+3];
    i += 4;
    NEED(4);
    out->age_add = ((uint32_t)msg[i] << 24) | ((uint32_t)msg[i+1] << 16) |
                   ((uint32_t)msg[i+2] << 8) | (uint32_t)msg[i+3];
    i += 4;

    NEED(1);
    { size_t n = msg[i++]; NEED(n);
      if (n > nonce_cap) return -1;
      for (size_t k = 0; k < n; k++) nonce[k] = msg[i + k];
      *nonce_len = n;
      i += n; }

    NEED(2);
    { size_t tlen = ((size_t)msg[i] << 8) | msg[i+1]; i += 2; NEED(tlen);
      if (tlen == 0 || tlen > sizeof out->ticket) return -1;
      for (size_t k = 0; k < tlen; k++) out->ticket[k] = msg[i + k];
      out->ticket_len = tlen;
      i += tlen; }

    NEED(2);
    { size_t extlen = ((size_t)msg[i] << 8) | msg[i+1]; i += 2; NEED(extlen); i += extlen; }

    if (i != len) return -1;
    #undef NEED
    return 0;
}

/* ------------------------------------------------------------------ */
/* Finished                                                           */
/* ------------------------------------------------------------------ */
void tls_finished_key(uint8_t out[32], const uint8_t base_secret[32])
{
    tls_hkdf_expand_label(out, 32, base_secret, "finished", 0, 0);
}

void tls_finished_verify_data(uint8_t out[32], const uint8_t finished_key[32],
                              const uint8_t transcript_hash[32])
{
    hmac_sha256(finished_key, 32, transcript_hash, 32, out);
}

int tls_check_finished(const uint8_t finished_key[32],
                       const uint8_t transcript_hash[32],
                       const uint8_t received_verify_data[32])
{
    uint8_t expected[32];
    tls_finished_verify_data(expected, finished_key, transcript_hash);
    uint8_t diff = 0;
    for (int k = 0; k < 32; k++) diff |= (uint8_t)(expected[k] ^ received_verify_data[k]);
    return diff ? -1 : 0;
}
