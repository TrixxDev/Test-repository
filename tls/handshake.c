/* TLS 1.3 handshake message layer (RFC 8446 §4) — see handshake.h. */
#include "handshake.h"
#include "key_schedule.h"
#include "hmac_sha256.h"
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
static void w_bytes(wbuf *b, const uint8_t *d, size_t n) { for (size_t i = 0; i < n; i++) w_u8(b, d[i]); }

/* reserve a 2-byte (or 3-byte) length to be filled in by w_close* */
static size_t w_open16(wbuf *b) { size_t at = b->len; w_u16(b, 0); return at; }
static void   w_close16(wbuf *b, size_t at) { size_t n = b->len - at - 2; b->p[at] = (uint8_t)(n >> 8); b->p[at+1] = (uint8_t)n; }
static size_t w_open24(wbuf *b) { size_t at = b->len; w_u24(b, 0); return at; }
static void   w_close24(wbuf *b, size_t at) { size_t n = b->len - at - 3; b->p[at] = (uint8_t)(n >> 16); b->p[at+1] = (uint8_t)(n >> 8); b->p[at+2] = (uint8_t)n; }

int tls_build_client_hello(uint8_t *out, size_t cap,
                           const uint8_t random[32],
                           const uint8_t x25519_pub[32],
                           const char *server_name)
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

    w_close16(&b, exts);
    w_close24(&b, hs);

    return b.err ? -1 : (int)b.len;
}

/* ------------------------------------------------------------------ */
/* ServerHello parser (bounds-checked)                                */
/* ------------------------------------------------------------------ */
int tls_parse_server_hello(const uint8_t *msg, size_t len,
                           uint16_t *cipher_suite,
                           uint8_t server_x25519_pub[32])
{
    size_t i = 0;
    #define NEED(n) do { if (i + (n) > len) return -1; } while (0)

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
        }
        i += elen;
    }
    #undef NEED
    return have_key_share ? 0 : -1;
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
