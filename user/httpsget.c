/* httpsget — Aurora's userspace HTTPS client (14.0.3b / 14.0.4 in QEMU; 15.2
 * adds redirects; 15.4 adds HTTP keep-alive; 15.8 adds a multi-origin
 * session cache; 15.9 adds cookies; 15.10 adds gzip; 16.1 adds HTTP POST;
 * 16.2 adds HTTP authentication; 16.3 makes redirects RFC-correct for a
 * request with a body).
 *
 * HTTP POST (Phase 16.1, opening the "Web Platform" series that follows
 * HTTPS v2): `httpsget --post <host> <path> <body> [now_unix]` sends `body`
 * (a single whitespace-free CLI argument -- Aurora's shell has no quoting)
 * as application/x-www-form-urlencoded, with an auto-computed
 * Content-Length. What happens to the method/body across a redirect (Phase
 * 16.3) follows RFC 7231/7238 by status code: 307 and 308 resend the exact
 * same method and body on the next hop, while 301/302/303 downgrade to a
 * bodyless GET -- matching what browsers have done since long before it
 * was standardized.
 *
 * The end-to-end acceptance program: the SAME freestanding TLS/x509/crypto stack,
 * driven over Aurora's OWN network stack (DNS -> TCP -> TLS 1.3 -> HTTP/1.1),
 * fetching a real web page. Deliberately dumb and diagnostic — no HTTP/2, no
 * pipelining, no concurrency of any kind (requests are always fully
 * sequential; the session cache below holds multiple *idle* connections, it
 * never uses more than one at a time).
 *
 * Multi-origin session cache (Phase 15.8): a small fixed array of
 * TLS_SESSION_SLOTS (4) slots, each bound to one origin (scheme/host/port).
 * Deliberately NOT a general "connection pool" -- there is no concurrency to
 * pool for, and no background thread, timer, or cleanup daemon; it is
 * exactly as synchronous as every phase before it. What it actually buys:
 * a redirect chain that bounces between origins (A -> B -> A) no longer pays
 * for a fresh TCP+TLS handshake back to A just because a hop to B came in
 * between -- A's slot may still hold a live, open connection (reused for
 * free) or, failing that, still hold A's session ticket from the earlier
 * visit (Phase 15.7 resumption instead of a full handshake). A slot's
 * connection closes (its ticket does not) the moment a response on it isn't
 * reusable(); the whole cache is walked and closed once at the very end of
 * the process. When all 4 slots are bound to *different* origins and a 5th
 * is needed, the least-recently-used origin is evicted (its live connection
 * closed, its ticket forgotten) -- this is a size limit on distinct origins
 * touched, not a request queue or a connection-reuse policy change.
 *
 * Cookies (Phase 15.9): a compact, process-lifetime jar (user/cookiejar.c,
 * RFC 6265). Every Set-Cookie header on a response is parsed and stored;
 * every request sends back whatever matches its host/path (and, for a
 * Secure cookie, only over https) as a single "Cookie:" header. This is what
 * lets a page keep a session across a redirect or a second path in the same
 * run -- without it, a login/consent flow or anything session-based simply
 * can't work. SameSite/Priority/Partitioned and other newer attributes are
 * parsed as "unknown" and silently ignored, matching the jar's own stated
 * scope (see cookiejar.h).
 *
 * gzip (Phase 15.10): every request asks for "Accept-Encoding: gzip". A
 * "Content-Encoding: gzip" response (and not also chunked -- see below) is
 * decompressed genuinely incrementally, in resp_feed(), as each new chunk of
 * wire bytes arrives -- never the whole compressed body at once. A response
 * that's BOTH chunked and gzip-encoded (legal, but rare in practice) falls
 * back to the pre-existing non-streaming dechunk() pass followed by a single
 * one-shot gzip_feed() over the result, at display time -- the same
 * non-streaming shape dechunk() itself has always had.
 *
 *   usage: httpsget <host> <path> [path...] [now_unix]   (default path "/", port 443)
 *   e.g.   httpsget github.com /
 *          httpsget example.com / /style.css /logo.png
 *
 * Keep-alive (Phase 15.4): the goal is narrow -- skip a redundant TCP+TLS
 * handshake when the server said we don't need one, nothing more. Each of
 * several paths (given on the command line, or reached via a same-origin
 * redirect, or -- since 15.8 -- a redirect back to a previously-visited
 * origin) reuses the open connection when the previous response said
 * "Connection: keep-alive" (or defaulted to it under HTTP/1.1) AND had a
 * determinate, bounded length (Content-Length, not chunked, not huge) --
 * otherwise a fresh connection is opened, exactly like every phase before
 * this one. Reuse is optimistic: the next request is just sent on the kept-
 * open socket, and if that write fails (the peer already closed it -- Aurora
 * has no non-blocking way to check liveness up front, see docs/SECURITY.md
 * Step 15.4), the connection is dropped and one fresh reconnect is tried, no
 * attempt to resurrect it. Deliberately NOT here: pipelining, concurrent
 * requests, or a persistent DNS cache -- those are a different, later kind
 * of feature.
 *
 * Redirects (301/302/303/307/308, Phase 15.2) still restart DNS on a host
 * change and the TLS handshake on a scheme change; a same-origin redirect
 * whose predecessor allowed keep-alive reuses the connection instead.
 *
 * Session resumption (Phase 15.7): each session-cache slot remembers the
 * most recent NewSessionTicket for its origin. A fresh connection to a
 * slot with an unexpired ticket offers its PSK (tls_conn_offer_psk) instead
 * of doing a full certificate-based handshake; if the server doesn't select
 * it, RFC 8446 §4.1.4 has the FSM fall back to a full handshake
 * transparently -- no special-casing needed here. Tickets only live for
 * this process's lifetime (no persistence across invocations) and only for
 * as long as their origin's slot isn't evicted, so this pays off within one
 * run touching the same origin more than once (several non-keep-alive-
 * reusable fetches, a forced reconnect, or -- since 15.8 -- a redirect back
 * to an origin whose slot survived).
 *
 * Trust store: a curated set of public CA roots (user/ca_roots.h). A site whose
 * whole chain is RSA-PKCS1-SHA256, ECDSA-P256-SHA256 or ECDSA-P384-SHA384
 * verifies against an RSA or ECDSA root (15.1).
 *
 * Aurora has no wall clock, so the validity instant is a build-time constant
 * (overridable via a purely-numeric argument) — keep it inside the target
 * cert's window. */
#include "libc.h"
#include "driver.h"
#include "conn.h"
#include "client.h"
#include "x509.h"
#include "cert.h"
#include "ca_roots.h"
#include "url.h"
#include "http.h"
#include "gzip.h"
#include "cookiejar.h"
#include "base64.h"

#define HTTPSGET_NOW 1782864000ULL   /* 2026-07-01; override via a numeric argument */
#define MAX_REDIRECTS 20             /* hop ceiling; visited[] also catches loops earlier */
#define MAX_PATHS     16
#define AUTH_TOKEN_MAX  512          /* raw bearer token or "user:pass" length cap (Phase 16.2) */
#define AUTH_HEADER_MAX (8 + 4 * ((AUTH_TOKEN_MAX + 2) / 3))  /* "Basic "/"Bearer " + base64 worst case */
#define FETCH_REUSE_MAX_BODY (64u * 1024u)  /* don't bother draining a response this big just to reuse the connection */
#define POST_BODY_MAX 4096           /* a diagnostic CLI, not a general uploader (Phase 16.1) */
#define REQ_BUF_MAX   (2048 + POST_BODY_MAX)  /* headers (incl. a full Cookie: line) + body */

static x509_cert         g_roots[CA_ROOTS_N];
/* Outgoing-record scratch: sized for REQ_BUF_MAX plaintext plus TLS/AEAD
 * overhead (record header + auth tag, a few dozen bytes) sealed into one
 * record -- comfortably under TLS_RECORD_MAX_PLAINTEXT (16 KiB), so a POST
 * body never needs to span multiple records. Also reused for the handshake
 * scratch and for raw incoming reads, both far smaller. */
static uint8_t           g_scratch[REQ_BUF_MAX + 256];
static uint8_t           g_plain[17000];
static uint8_t           g_resp[8192];      /* captured response prefix: status + headers + a
                                             * body preview (only ~512 B of body is shown), so a
                                             * few KiB suffices -- not the whole transfer (15.0.4). */
static struct url        g_visited[MAX_REDIRECTS + 1];

static cookie_jar g_cookies;   /* process-lifetime (Phase 15.9) */

/* HTTP authentication (Phase 16.2): a single Authorization header value,
 * fixed for the whole run, scoped to the origin it was given for --
 * fetch_one() only actually sends it on a request whose scheme/host/port
 * matches g_auth_origin (same_origin()), so a redirect to a different
 * origin never leaks credentials to it (this is stricter than what most
 * real HTTP clients do by default, deliberately). */
static char       g_auth_header[AUTH_HEADER_MAX];
static int        g_auth_len;
static int        g_has_auth;
static struct url g_auth_origin;

/* Multi-origin session cache (Phase 15.8): one slot per origin, holding
 * whatever a real client would want to remember about it between requests --
 * a still-open connection (conn_open), and/or a session ticket (has_ticket)
 * that survives even after the connection closes. tls_conn/tls_record_reader
 * are large (~37 KiB / ~33 KiB, mostly reassembly buffers), so this array
 * MUST stay a global (see the 15.10 stack-overflow postmortem in
 * docs/SECURITY.md) -- never a local, not even conditionally. */
#define TLS_SESSION_SLOTS 4
typedef struct {
    int         in_use;       /* bound to some origin (may or may not have a live connection) */
    struct url  origin;       /* https/host/port identify it; .path is unused */
    int         conn_open;    /* fd/conn/reader below are a live, reusable TCP+TLS session */
    int         fd;
    tls_conn    conn;
    tls_record_reader reader;
    int         has_ticket;
    tls_session_ticket ticket;
    uint64_t    last_used;    /* LRU clock value (see g_slot_clock), not wall time */
} session_slot;
static session_slot g_slots[TLS_SESSION_SLOTS];
static uint64_t     g_slot_clock;

static int xport_read(void *ctx, uint8_t *buf, size_t cap)
{ session_slot *s = ctx; return read(s->fd, buf, (int)cap); }
static int xport_write(void *ctx, const uint8_t *buf, size_t len)
{ session_slot *s = ctx; return write(s->fd, buf, (int)len); }
static int write_all(int fd, const uint8_t *b, int n)
{ int s = 0; while (s < n) { int w = write(fd, b + s, n - s); if (w <= 0) return -1; s += w; } return 0; }
static void trace_sink(void *ctx, tls_event ev, uint32_t detail)
{ (void)ctx; (void)detail; printf("[TLS] %s\n", tls_event_name(ev)); }

static void app(char *d, int *n, const char *s){ for (int i = 0; s[i]; i++) d[(*n)++] = s[i]; }

static unsigned long parse_ul(const char *s){ unsigned long v=0; while (*s>='0'&&*s<='9') v=v*10+(*s++-'0'); return v; }

static int find_header_end(const uint8_t *r, int len)
{ for (int i=0;i+3<len;i++) if(r[i]=='\r'&&r[i+1]=='\n'&&r[i+2]=='\r'&&r[i+3]=='\n') return i+4; return -1; }

static int dechunk(const uint8_t *in, int len, uint8_t *out, int outcap)
{
    int i=0,o=0;
    for (;;) {
        int sz=0,any=0;
        while (i<len){int c=in[i],d; if(c>='0'&&c<='9')d=c-'0'; else if((c|32)>='a'&&(c|32)<='f')d=(c|32)-'a'+10; else break; sz=sz*16+d; any=1; i++;}
        if (!any) return o>0?o:-1;
        while (i<len && in[i]!='\n') i++; if (i<len) i++;
        if (sz==0) break;
        if (i+sz>len || o+sz>outcap) return o;
        memcpy(out+o,in+i,sz); o+=sz; i+=sz;
        if (i<len && in[i]=='\r') i++; if (i<len && in[i]=='\n') i++;
    }
    return o;
}

static int url_eq(const struct url *a, const struct url *b)
{
    return a->https == b->https && a->port == b->port &&
           strcmp(a->host, b->host) == 0 && strcmp(a->path, b->path) == 0;
}

/* Same connection identity (scheme/host/port), regardless of path -- what
 * matters for deciding whether an open session can serve the next request.
 * url_eq() above compares the whole URL including path; that's the right
 * check for redirect-loop detection, but the wrong one for reuse (two
 * different paths on the same origin are exactly the case keep-alive is for). */
static int same_origin(const struct url *a, const struct url *b)
{
    return a->https == b->https && a->port == b->port && strcmp(a->host, b->host) == 0;
}

/* May the connection this response arrived on be reused for another request?
 * Server-offered keep-alive is necessary but not sufficient: a body without a
 * determinate length (no Content-Length, or chunked) can only be known to
 * have ended when the connection closes, which defeats reuse; and a body
 * that's merely very large isn't worth draining to the end just to save one
 * handshake. */
static int reusable(const struct http_response *hr)
{
    return hr->keep_alive && (unsigned)hr->content_length <= FETCH_REUSE_MAX_BODY;
}

/* Find the slot already bound to `u`'s origin, or bind a fresh one: an
 * unused slot if one exists, else the least-recently-used bound slot
 * (evicting it -- closing its live connection if any, forgetting its
 * ticket). Every returned slot has its LRU clock refreshed, so a slot found
 * this way is never immediately re-evicted by the very next lookup. */
static session_slot *slot_find_or_alloc(const struct url *u)
{
    session_slot *free_slot = 0, *lru_slot = &g_slots[0];
    for (int i = 0; i < TLS_SESSION_SLOTS; i++) {
        session_slot *s = &g_slots[i];
        if (s->in_use && same_origin(&s->origin, u)) { s->last_used = ++g_slot_clock; return s; }
        if (!s->in_use && !free_slot) free_slot = s;
        if (s->in_use && s->last_used < lru_slot->last_used) lru_slot = s;
    }
    session_slot *s = free_slot ? free_slot : lru_slot;
    if (s->in_use) {
        if (s->conn_open) close(s->fd);
        printf("[httpsget] session cache: evicting %s:%d for %s:%d\n",
               s->origin.host, s->origin.port, u->host, u->port);
    }
    s->in_use = 1;
    s->origin = *u;
    s->conn_open = 0;
    s->has_ticket = 0;
    s->last_used = ++g_slot_clock;
    return s;
}

static void slot_close(session_slot *s)
{
    if (s->conn_open) close(s->fd);
    s->conn_open = 0;
}

static void close_all_slots(void)
{
    for (int i = 0; i < TLS_SESSION_SLOTS; i++) slot_close(&g_slots[i]);
}

static void app_uint(char *d, int *n, unsigned v)
{
    char t[10]; int tn = 0;
    do { t[tn++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (tn > 0) d[(*n)++] = t[--tn];
}

/* "<method> <path> HTTP/1.1\r\nHost: <host>[:<port>]\r\nUser-Agent: ...\r\n
 * Connection: keep-alive\r\n[Cookie: ...\r\n][Content-Type: ...\r\nContent-
 * Length: N\r\n]\r\n[body]" -- the port is included only when it isn't the
 * scheme default. We always ask for keep-alive: it costs nothing (the
 * caller closes the connection itself once it decides not to reuse it --
 * see reusable()), and asking only on "the requests that need it" would
 * require knowing in advance whether a redirect is coming, which we don't.
 * The Cookie header (Phase 15.9) is built fresh per request from whatever's
 * in the jar right now -- host/path/https-scoped, so a redirect to a
 * different origin naturally sends a different (or no) cookie set.
 *
 * `body`/`bodylen` (Phase 16.1) are optional (NULL/0 for a bodyless
 * request); when present they're sent as application/x-www-form-urlencoded
 * -- the one body shape this client's CLI can actually construct (a single
 * whitespace-free token; Aurora's shell has no quoting, see main()).
 *
 * `auth_header`/`auth_len` (Phase 16.2) are an optional pre-built
 * Authorization value ("Basic <base64>" or "Bearer <token>"; NULL/0 for
 * none) -- the caller (fetch_one()) decides per-hop whether this request's
 * origin still matches the one credentials were given for. */
static void build_request(char *req, int *rn, const struct url *u, uint64_t now,
                          const char *method, const uint8_t *body, int bodylen,
                          const char *auth_header, int auth_len)
{
    *rn = 0;
    app(req, rn, method); req[(*rn)++] = ' '; app(req, rn, u->path); app(req, rn, " HTTP/1.1\r\nHost: ");
    app(req, rn, u->host);
    int defport = u->https ? 443 : 80;
    if (u->port != defport) {
        req[(*rn)++] = ':';
        app_uint(req, rn, (unsigned)u->port);
    }
    app(req, rn, "\r\nUser-Agent: Aurora-httpsget/0.3\r\nConnection: keep-alive\r\nAccept-Encoding: gzip\r\n");

    char cookie_hdr[512];
    int clen = cookie_jar_build_header(&g_cookies, u->host, u->path, u->https, now, cookie_hdr, sizeof cookie_hdr);
    if (clen > 0) {
        app(req, rn, "Cookie: ");
        for (int i = 0; i < clen; i++) req[(*rn)++] = cookie_hdr[i];
        app(req, rn, "\r\n");
    }
    if (auth_header && auth_len > 0) {
        app(req, rn, "Authorization: ");
        for (int i = 0; i < auth_len; i++) req[(*rn)++] = auth_header[i];
        app(req, rn, "\r\n");
    }
    if (body && bodylen > 0) {
        app(req, rn, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
        app_uint(req, rn, (unsigned)bodylen);
        app(req, rn, "\r\n");
    }
    app(req, rn, "\r\n");
    if (body && bodylen > 0)
        for (int i = 0; i < bodylen; i++) req[(*rn)++] = (char)body[i];
}

typedef struct {
    struct http_response hr;
    int rlen;             /* bytes captured into g_resp (<= sizeof g_resp) */
    int closed;           /* did the peer actually close the TCP connection this exchange */
} fetch_result_t;

/* Response accumulation state for the in-flight fetch_request() call. Reset by
 * resp_reset(); fed via resp_feed() as bytes arrive off the wire (decrypted
 * TLS application data, or raw bytes for plain HTTP) regardless of transport;
 * resp_done() says whether we've now consumed the *entire* response body (not
 * just our g_resp preview), which is required before the connection can be
 * safely reused for a second request. */
static int  g_rlen, g_total, g_hdrs_done, g_target;
static struct http_response g_hr;

/* Decompressed body preview (Phase 15.10), filled incrementally by
 * feed_gzip() as raw (compressed) body bytes arrive -- g_resp only ever
 * holds the *wire* bytes (headers, and compressed body for a gzip
 * response), so this is the only place the actual page content lands when
 * Content-Encoding: gzip is in play. */
#define GZIP_BODY_PREVIEW (4u * 1024u)
static uint8_t  g_body[GZIP_BODY_PREVIEW];
static int      g_body_len;
static gzip_ctx g_gz;
static int      g_gz_active;    /* a gzip decode is in progress for the current response */

static void resp_reset(void)
{
    g_rlen = 0; g_total = 0; g_hdrs_done = 0; g_target = -1;
    memset(&g_hr, 0, sizeof g_hr);
    g_body_len = 0;
    g_gz_active = 0;
}

/* Feed newly-arrived (compressed) body bytes through the incremental gzip
 * decoder, appending whatever decompresses out of them into g_body up to
 * its cap. A malformed stream, or reaching the cap, just stops decoding
 * early (same "preview, not the whole thing" spirit as g_resp's own cap) --
 * never fatal to the fetch itself. */
static void feed_gzip(const uint8_t *data, int n)
{
    if (!g_gz_active || n <= 0) return;
    size_t pos = 0;
    while (pos < (size_t)n && g_body_len < (int)sizeof g_body) {
        size_t in_used, out_len; int done;
        int rc = gzip_feed(&g_gz, data + pos, (size_t)n - pos,
                           g_body + g_body_len, sizeof g_body - (size_t)g_body_len,
                           &in_used, &out_len, &done);
        g_body_len += (int)out_len;
        pos += in_used;
        if (rc != 0 || done) { g_gz_active = 0; break; }
        if (in_used == 0 && out_len == 0) break;   /* no progress possible right now */
    }
}

static void resp_feed(const uint8_t *data, int n)
{
    if (n <= 0) return;
    int total_before = g_total;
    g_total += n;
    if (g_rlen < (int)sizeof g_resp) {
        int c = (g_rlen + n <= (int)sizeof g_resp) ? n : (int)sizeof g_resp - g_rlen;
        memcpy(g_resp + g_rlen, data, c);
        g_rlen += c;
    }
    if (!g_hdrs_done) {
        int he = find_header_end(g_resp, g_rlen);
        if (he > 0) {
            g_hdrs_done = 1;
            http_parse((const char*)g_resp, g_rlen, &g_hr);
            if (reusable(&g_hr))
                g_target = g_hr.header_len + g_hr.content_length;   /* drain exactly to the boundary */
            if (g_hr.gzip && !g_hr.chunked) {
                /* Genuinely incremental decoding only covers the common
                 * gzip-without-chunking case; chunked+gzip together falls
                 * back to a one-shot pass at display time (fetch_one()) --
                 * dechunk() itself isn't incremental either, so that
                 * combination was never going to be truly streaming. */
                gzip_init(&g_gz);
                g_gz_active = 1;
                /* `he` is a position in the same byte numbering as
                 * total_before: headers are always far under g_resp's cap,
                 * so g_total cannot yet have outrun what's captured there. */
                int hdr_bytes_here = he - total_before;
                if (hdr_bytes_here < 0) hdr_bytes_here = 0;
                if (hdr_bytes_here > n) hdr_bytes_here = n;
                feed_gzip(data + hdr_bytes_here, n - hdr_bytes_here);
            }
        }
    } else if (g_gz_active) {
        feed_gzip(data, n);
    }
}

/* True once the whole response body has been consumed (only meaningful when
 * reusable() held at header time -- otherwise we stop at the g_resp cap
 * instead, exactly like every phase before 15.4, and just close afterward). */
static int resp_done(void) { return g_target >= 0 && g_total >= g_target; }

#define FETCH_OK    0
#define FETCH_STALE (-2)   /* the write failed: a reused connection was already dead */

/* Open a fresh TCP connection to `u` into `slot` (a DNS lookup if `u->host`
 * isn't a literal), doing a TLS 1.3 handshake first if `u->https` -- offering
 * `slot`'s cached ticket for resumption if it has one. On success,
 * slot->conn_open = 1. On failure, a diagnostic has already been printed and
 * slot->conn_open is left however it was (0 -- the caller must have already
 * closed any live connection this slot held, see fetch()). */
static int fetch_begin(session_slot *slot, const struct url *u, uint64_t now)
{
    slot->fd = inet_socket();
    if (slot->fd < 0) { fprintf(2, "httpsget: inet_socket failed\n"); return -1; }
    int rc = inet_connect(slot->fd, u->host, u->port);
    if (rc == -2) { fprintf(2, "httpsget: DNS resolution failed for %s\n", u->host); close(slot->fd); return -1; }
    if (rc != 0)  { fprintf(2, "httpsget: TCP connect failed (%d)\n", rc); close(slot->fd); return -1; }
    printf("[httpsget] TCP connected to %s:%d\n", u->host, u->port);

    if (u->https) {
        uint8_t priv[32], crand[32];
        unsigned seed = perf_us() ^ (unsigned)getpid();
        for (int i = 0; i < 32; i++) { seed = seed*1103515245u + 12345u;
            priv[i] = (uint8_t)(i*7+1) ^ (uint8_t)(seed>>16); crand[i] = (uint8_t)(i*3+9) ^ (uint8_t)(seed>>8); }

        tls_conn_init(&slot->conn, u->host, priv, crand);
        tls_client_set_trust(&slot->conn.fsm, g_roots, CA_ROOTS_N, now);
        tls_conn_set_trace(&slot->conn, trace_sink, 0);

        if (slot->has_ticket) {
            tls_conn_offer_psk(&slot->conn, &slot->ticket, now * 1000);
            printf("[httpsget] offering cached session ticket for %s:%d\n", u->host, u->port);
        }

        tls_reader_init(&slot->reader);

        tls_transport t = { xport_read, xport_write, slot };
        int r = tls_driver_handshake(&slot->conn, &slot->reader, &t, g_scratch, sizeof g_scratch);
        if (r != TLS_DRIVE_OK) {
            const char *why = "?";
            if (slot->conn.fsm.error == TLS_ERR_CERT) {
                switch (slot->conn.fsm.cert_reason) {
                    case TLS_CERT_UNTRUSTED:    why = "chain does not build to a trusted root"; break;
                    case TLS_CERT_EXPIRED:      why = "leaf expired (vs the build-time clock)"; break;
                    case TLS_CERT_NOT_YET:      why = "leaf not yet valid (vs the build-time clock)"; break;
                    case TLS_CERT_BAD_HOSTNAME: why = "hostname does not match the leaf SAN"; break;
                    case TLS_CERT_MALFORMED:    why = "certificate message malformed"; break;
                    default: why = "certificate rejected"; break;
                }
                fprintf(2, "[httpsget] TLS FAILED (%s): certificate validation -- %s\n"
                           "           (driver=%d cert_reason=%d). The handshake itself succeeded;\n"
                           "           the chain is not verifiable against the %u-root trust store.\n",
                        u->host, why, r, slot->conn.fsm.cert_reason, (unsigned)CA_ROOTS_N);
            } else {
                const char *e = slot->conn.fsm.error == TLS_ERR_AUTH ? "CertificateVerify (key ownership)"
                              : slot->conn.fsm.error == TLS_ERR_PROTOCOL ? "protocol/record" : "transport";
                fprintf(2, "[httpsget] TLS FAILED (%s): %s (driver=%d tls_error=%d)\n",
                        u->host, e, r, (int)slot->conn.fsm.error);
            }
            close(slot->fd); return -1;
        }
        if (slot->conn.fsm.psk_accepted) {
            /* Resumed handshake: WAIT_CERT/WAIT_CV are skipped entirely (RFC
             * 8446 §2.2), so certs/cv_scheme are stale leftovers from
             * whatever full handshake this slot's connection last did --
             * printing them here would be misleading, not just uninteresting. */
            printf("[TLS] Session resumed (PSK accepted) -- no certificate exchanged\n");
        } else {
            int lk = slot->conn.fsm.certs.count ? slot->conn.fsm.certs.certs[0].pubkey_algo : 0;
            const char *kt = lk == X509_PK_EC ? "EC P-256" : lk == X509_PK_EC384 ? "EC P-384" : "RSA";
            uint16_t cv = slot->conn.fsm.cv_scheme;
            const char *cvn = cv == TLS_SIG_ECDSA_SECP384R1_SHA384 ? "ecdsa_secp384r1_sha384"
                            : cv == TLS_SIG_ECDSA_SECP256R1_SHA256 ? "ecdsa_secp256r1_sha256"
                            : cv == TLS_SIG_RSA_PSS_RSAE_SHA256     ? "rsa_pss_rsae_sha256"
                            : cv == TLS_SIG_RSA_PKCS1_SHA256        ? "rsa_pkcs1_sha256" : "?";
            printf("[TLS] Certificate depth=%d  Leaf key=%s  CV scheme=%s\n",
                   (int)slot->conn.fsm.certs.count, kt, cvn);
        }
        printf("[TLS] CONNECTED\n");
    }
    slot->conn_open = 1;
    return 0;
}

/* Send one request (`method`, optionally with a body -- Phase 16.1) for
 * u->path over `slot`'s ALREADY-OPEN session (caller guarantees
 * same_origin(&slot->origin, u)) and read the response into g_resp / *out.
 * Returns FETCH_OK if a response was obtained (status may be anything,
 * including non-2xx), FETCH_STALE if the write itself failed -- the reused connection
 * was already dead; not a bug, Aurora has no non-blocking way to check that
 * up front, see the header comment -- or -1 on any other transport failure
 * (diagnostic already printed, unrecoverable). */
static int fetch_request(session_slot *slot, const struct url *u, uint64_t now,
                         const char *method, const uint8_t *body, int bodylen,
                         const char *auth_header, int auth_len, fetch_result_t *out)
{
    resp_reset();
    char req[REQ_BUF_MAX]; int rn;
    build_request(req, &rn, u, now, method, body, bodylen, auth_header, auth_len);

    int closed = 0;
    if (slot->origin.https) {
        int sl = tls_conn_send_app(&slot->conn, (const uint8_t*)req, (size_t)rn, g_scratch, sizeof g_scratch);
        if (sl < 0) return FETCH_STALE;
        if (write_all(slot->fd, g_scratch, sl) != 0) return FETCH_STALE;
        printf("[httpsget] %s %s HTTP/1.1 sent\n", method, u->path);

        for (;;) {
            const uint8_t *rec; size_t rl; int cc;
            while ((cc = tls_reader_next(&slot->reader, &rec, &rl)) == 1) {
                size_t pl = 0;
                int rr = tls_conn_recv_app(&slot->conn, rec, rl, g_plain, sizeof g_plain, &pl);
                if (rr == TLS_CONN_ERR_ALERT) { closed = 1; goto https_done; }
                if (rr < 0) { fprintf(2, "[httpsget] recv_app error %d\n", rr); goto https_done; }
                resp_feed(g_plain, (int)pl);
                /* A NewSessionTicket may ride along with (or instead of) app
                 * data on any read once CONNECTED (Phase 15.7); it's stored
                 * on the slot itself, so it outlives this one connection. */
                { tls_session_ticket t;
                  if (tls_conn_take_ticket(&slot->conn, &t)) {
                      t.obtained_ms = now * 1000;
                      slot->ticket = t; slot->has_ticket = 1;
                      printf("[httpsget] session ticket cached for %s:%d (lifetime=%us)\n",
                             u->host, u->port, t.lifetime_secs);
                  } }
                if (resp_done()) goto https_done;
            }
            if (cc < 0) { fprintf(2, "[httpsget] malformed record\n"); break; }
            if (g_target < 0 && g_rlen >= (int)sizeof g_resp) break;   /* not reusable: preview cap reached */
            int n = read(slot->fd, g_scratch, sizeof g_scratch);
            if (n <= 0) { closed = 1; break; }
            tls_reader_feed(&slot->reader, g_scratch, (size_t)n);
        }
        https_done: ;
    } else {
        if (write_all(slot->fd, (const uint8_t*)req, rn) != 0) return FETCH_STALE;
        printf("[httpsget] %s %s HTTP/1.1 sent (plain HTTP)\n", method, u->path);

        for (;;) {
            if (resp_done()) break;
            if (g_target < 0 && g_rlen >= (int)sizeof g_resp) break;
            int n = read(slot->fd, g_scratch, sizeof g_scratch);
            if (n <= 0) { closed = 1; break; }
            resp_feed(g_scratch, n);
        }
    }

    /* A connection that closed having delivered nothing at all is the other
     * half of the staleness race: the write above can land just before the
     * peer's earlier FIN/RST is actually processed (net_poll() hasn't drained
     * it yet) and appear to succeed, with the dead connection only showing
     * itself on the read that follows. Either way, an empty closed response
     * on a reuse attempt means "the old connection was already gone," not
     * "the server answered with nothing" -- treat it the same as a failed
     * write so the caller reconnects instead of reporting a bogus response. */
    if (closed && g_total == 0) return FETCH_STALE;

    if (g_hdrs_done) {
        for (int occ = 0; ; occ++) {
            int vs, vl;
            if (!http_find_header((const char*)g_resp, g_hr.header_len, "Set-Cookie:", occ, &vs, &vl)) break;
            cookie_jar_set(&g_cookies, (const char*)g_resp + vs, vl, u->host, u->path, u->https, now);
            char preview[80]; int pn = vl < (int)sizeof(preview) - 1 ? vl : (int)sizeof(preview) - 1;
            memcpy(preview, g_resp + vs, (size_t)pn); preview[pn] = 0;
            printf("[httpsget] cookie stored: %s\n", preview);
        }
    }

    out->hr    = g_hr;
    out->rlen  = g_rlen;
    out->closed = closed;
    return FETCH_OK;
}

/* Find (or bind) `u`'s session-cache slot, reuse its open connection if it
 * has one, reconnect (offering its cached ticket, if any) otherwise, then
 * send one request and read the response. Returns 0 on a response obtained
 * (fr is filled), -1 on an unrecoverable transport failure (diagnostic
 * already printed, caller should give up). */
static int fetch(const struct url *u, uint64_t now, const char *method,
                 const uint8_t *body, int bodylen,
                 const char *auth_header, int auth_len, fetch_result_t *out)
{
    session_slot *slot = slot_find_or_alloc(u);
    if (slot->conn_open) {
        printf("[httpsget] reusing open connection to %s:%d (keep-alive)\n", u->host, u->port);
        int rc = fetch_request(slot, u, now, method, body, bodylen, auth_header, auth_len, out);
        if (rc == FETCH_OK) return 0;
        if (rc != FETCH_STALE) return -1;
        printf("[httpsget] reused connection to %s:%d was already closed -- reconnecting\n", u->host, u->port);
        slot_close(slot);
    }
    if (fetch_begin(slot, u, now) != 0) return -1;
    int rc = fetch_request(slot, u, now, method, body, bodylen, auth_header, auth_len, out);
    if (rc == FETCH_OK) return 0;
    if (rc == FETCH_STALE)
        fprintf(2, "[httpsget] connection to %s:%d closed before the request could be sent\n", u->host, u->port);
    return -1;
}

/* Fetch one top-level path (following redirects, Phase 15.2) and print its
 * result. Returns the final HTTP status (0 if no valid response was ever
 * obtained), or -1 on an unrecoverable transport failure. `label` is printed
 * as a header when there's more than one path in this run.
 *
 * `method`/`post_body`/`post_bodylen` (Phase 16.1) start as given for the
 * first request (hop 0) and are then re-decided after every redirect
 * response, per RFC 7231/7238 (Phase 16.3): 307 and 308 preserve the
 * current method and body unchanged onto the next hop, while every other
 * redirect status (301/302/303) downgrades to a bodyless GET, matching
 * what browsers have done since long before it was standardized. */
static int fetch_one(const char *host, const char *path, uint64_t now, const char *label,
                     const char *method, const uint8_t *post_body, int post_bodylen)
{
    struct url u; memset(&u, 0, sizeof u);
    u.https = 1; u.port = 443;
    { int i = 0; for (; host[i] && i < (int)sizeof(u.host) - 1; i++) u.host[i] = host[i]; u.host[i] = 0; }
    { int i = 0; for (; path[i] && i < (int)sizeof(u.path) - 1; i++) u.path[i] = path[i]; u.path[i] = 0; }
    if (!u.path[0]) { u.path[0] = '/'; u.path[1] = 0; }

    if (label) printf("[httpsget] ==== %s ====\n", label);

    int nvisited = 0, hop = 0;
    fetch_result_t fr;
    const char *req_method = method;
    const uint8_t *req_body = post_body;
    int req_bodylen = post_bodylen;

    for (;;) {
        for (int i = 0; i < nvisited; i++)
            if (url_eq(&g_visited[i], &u)) {
                fprintf(2, "[httpsget] redirect loop detected at %s://%s%s -- aborting\n",
                        u.https ? "https" : "http", u.host, u.path);
                return -1;
            }
        if (nvisited >= MAX_REDIRECTS + 1) {
            fprintf(2, "[httpsget] too many redirects (limit %d) -- aborting\n", MAX_REDIRECTS);
            return -1;
        }
        g_visited[nvisited++] = u;

        if (hop > 0)
            printf("[httpsget] -- hop %d/%d: %s %s://%s:%d%s\n", hop, MAX_REDIRECTS, req_method,
                   u.https ? "https" : "http", u.host, u.port, u.path);

        /* Authorization (Phase 16.2) is re-checked on every hop, not just
         * hop 0: it's scoped to whichever origin it was given for, so it
         * naturally keeps following same-origin redirects and just as
         * naturally stops the moment a redirect leaves that origin. */
        const char *cur_auth = (g_has_auth && same_origin(&g_auth_origin, &u)) ? g_auth_header : 0;
        int cur_auth_len = cur_auth ? g_auth_len : 0;
        if (fetch(&u, now, req_method, req_body, req_bodylen, cur_auth, cur_auth_len, &fr) != 0)
            return -1;    /* diagnostic already printed */
        /* Only this response's own slot closes -- a redirect to a different
         * origin (Phase 15.8) leaves every other origin's slot exactly as it
         * was, so a later hop back to one of them can still reuse it. */
        if (!reusable(&fr.hr)) slot_close(slot_find_or_alloc(&u));

        int st = fr.hr.status;
        int is_redirect = st == 301 || st == 302 || st == 303 || st == 307 || st == 308;
        if (!is_redirect) {
            int status = st;
            int hbe = fr.hr.header_len;
            int truncated = fr.hr.content_length >= 0
                           ? (hbe + fr.hr.content_length > fr.rlen)
                           : !fr.closed;
            printf("[httpsget] %d response bytes, status=%d%s\n", fr.rlen, status, truncated ? " (truncated preview)" : "");
            /* status line */
            int e = 0; while (e < fr.rlen && g_resp[e] != '\r' && g_resp[e] != '\n') e++;
            g_resp[e < (int)sizeof g_resp ? e : (int)sizeof g_resp - 1] = 0;
            printf("%s\n", (char*)g_resp);
            /* body preview -- decompressed already (in g_body) if this was a
             * plain gzip response; chunked+gzip together (rare) gets a one-
             * shot dechunk-then-gunzip pass here instead, since dechunk()
             * itself was never incremental either. */
            if (hbe > 0 && hbe <= fr.rlen) {
                static uint8_t body[8192]; int blen;
                if (fr.hr.gzip && fr.hr.chunked) {
                    static uint8_t dechunked[8192];
                    int dlen = dechunk(g_resp + hbe, fr.rlen - hbe, dechunked, (int)sizeof dechunked);
                    if (dlen < 0) dlen = 0;
                    static gzip_ctx gz; gzip_init(&gz);
                    size_t in_used, out_len; int done;
                    gzip_feed(&gz, dechunked, (size_t)dlen, body, sizeof body, &in_used, &out_len, &done);
                    blen = (int)out_len;
                } else if (fr.hr.gzip) {
                    blen = g_body_len;
                    memcpy(body, g_body, (size_t)blen);
                } else if (fr.hr.chunked) {
                    blen = dechunk(g_resp + hbe, fr.rlen - hbe, body, (int)sizeof body);
                } else {
                    blen = fr.rlen - hbe; if (blen > (int)sizeof body) blen = (int)sizeof body; memcpy(body, g_resp + hbe, blen);
                }
                int show = blen < 512 ? blen : 512;
                if (show > 0) { body[show < (int)sizeof body ? show : (int)sizeof body - 1] = 0;
                                printf("[body %d bytes, first %d]:\n%s\n", blen, show, (char*)body); }
            }
            const char *via = hop == 0 ? "" : " after redirects";
            if (status == 200) printf("\nhttpsget: 200 OK over Aurora TCP->TLS1.3->HTTP%s\n", via);
            else                printf("\nhttpsget: status=%d (not 200)%s\n", status, via);
            return status;
        }

        if (!fr.hr.location[0]) {
            fprintf(2, "[httpsget] redirect status %d with no usable Location header -- stopping\n", st);
            return st;
        }
        struct url next;
        if (url_resolve(&u, fr.hr.location, (int)strlen(fr.hr.location), &next) != 0) {
            fprintf(2, "[httpsget] could not resolve redirect Location '%s' -- stopping\n", fr.hr.location);
            return st;
        }
        printf("[httpsget] %d redirect -> %s\n", st, fr.hr.location);
        if (st != 307 && st != 308) { req_method = "GET"; req_body = 0; req_bodylen = 0; }
        u = next;
        hop++;
    }
}

int main(int argc, char **argv)
{
    const char *usage =
        "usage: httpsget [--post] [--auth-basic user:pass | --auth-bearer token] <host> <path> [path...] [now_unix]\n"
        "       httpsget [--auth-basic user:pass | --auth-bearer token] --post <host> <path> <body> [now_unix]\n";
    const char *method = "GET";
    const uint8_t *post_body = 0;
    int post_bodylen = 0;
    int argi = 1;

    /* Leading flags, any order: --post, and at most one of --auth-basic /
     * --auth-bearer (Phase 16.2). Each credential value is a single
     * whitespace-free CLI token -- Aurora's shell has no quoting. */
    for (;;) {
        if (argi < argc && strcmp(argv[argi], "--post") == 0) {
            method = "POST"; argi++; continue;
        }
        if (argi < argc && strcmp(argv[argi], "--auth-basic") == 0) {
            argi++;
            if (argi >= argc) { fprintf(2, "%s", usage); return 1; }
            int n = (int)strlen(argv[argi]);
            if (n > AUTH_TOKEN_MAX) { fprintf(2, "httpsget: --auth-basic value too long (max %d bytes)\n", AUTH_TOKEN_MAX); return 1; }
            g_auth_len = 0;
            app(g_auth_header, &g_auth_len, "Basic ");
            int bn = base64_encode((const uint8_t*)argv[argi], n, g_auth_header + g_auth_len, (int)sizeof(g_auth_header) - g_auth_len);
            if (bn < 0) { fprintf(2, "httpsget: --auth-basic value too long\n"); return 1; }
            g_auth_len += bn;
            g_has_auth = 1;
            argi++; continue;
        }
        if (argi < argc && strcmp(argv[argi], "--auth-bearer") == 0) {
            argi++;
            if (argi >= argc) { fprintf(2, "%s", usage); return 1; }
            int n = (int)strlen(argv[argi]);
            if (n > AUTH_TOKEN_MAX) { fprintf(2, "httpsget: --auth-bearer value too long (max %d bytes)\n", AUTH_TOKEN_MAX); return 1; }
            g_auth_len = 0;
            app(g_auth_header, &g_auth_len, "Bearer ");
            for (int i = 0; i < n; i++) g_auth_header[g_auth_len++] = argv[argi][i];
            g_has_auth = 1;
            argi++; continue;
        }
        break;
    }

    if (argc < argi + 1) { fprintf(2, "%s", usage); return 1; }
    const char *host = argv[argi++];
    const char *paths[MAX_PATHS]; int npaths = 0;
    uint64_t now = HTTPSGET_NOW;

    if (g_has_auth) {
        memset(&g_auth_origin, 0, sizeof g_auth_origin);
        g_auth_origin.https = 1; g_auth_origin.port = 443;
        int i = 0; for (; host[i] && i < (int)sizeof(g_auth_origin.host) - 1; i++) g_auth_origin.host[i] = host[i];
        g_auth_origin.host[i] = 0;
    }

    if (method[0] == 'P') {
        /* --post: exactly one path and one body token -- Aurora's shell has
         * no quoting (see build_request()'s doc comment), so the body is
         * whatever single whitespace-free argument follows the path,
         * typically an application/x-www-form-urlencoded string. */
        if (argi >= argc || argv[argi][0] != '/') { fprintf(2, "%s", usage); return 1; }
        paths[0] = argv[argi++]; npaths = 1;
        if (argi >= argc) { fprintf(2, "%s", usage); return 1; }
        post_body = (const uint8_t*)argv[argi];
        post_bodylen = (int)strlen(argv[argi]);
        if (post_bodylen > POST_BODY_MAX) { fprintf(2, "httpsget: body too large (max %d bytes)\n", POST_BODY_MAX); return 1; }
        argi++;
        if (argi < argc) now = (uint64_t)parse_ul(argv[argi]);
    } else {
        for (int i = argi; i < argc; i++) {
            if (argv[i][0] == '/') { if (npaths < MAX_PATHS) paths[npaths++] = argv[i]; }
            else now = (uint64_t)parse_ul(argv[i]);
        }
        if (npaths == 0) { paths[0] = "/"; npaths = 1; }
    }

    cookie_jar_init(&g_cookies);

    for (unsigned i = 0; i < CA_ROOTS_N; i++)
        if (x509_parse(ca_roots[i].der, ca_roots[i].len, &g_roots[i]) != 0) {
            fprintf(2, "httpsget: trust root %u (%s) failed to parse\n", i, ca_roots[i].name); return 1;
        }

    if (npaths == 1)
        printf("[httpsget] %s%s%s%s  (trust store: %u roots)\n", host, paths[0],
               post_body ? " (POST)" : "", g_has_auth ? " (auth)" : "", (unsigned)CA_ROOTS_N);
    else
        printf("[httpsget] %d paths from %s  (trust store: %u roots)\n", npaths, host, (unsigned)CA_ROOTS_N);

    int last_status = 0;
    for (int pi = 0; pi < npaths; pi++) {
        int st = fetch_one(host, paths[pi], now, npaths > 1 ? paths[pi] : 0,
                           method, post_body, post_bodylen);
        if (st < 0) { close_all_slots(); return 1; }
        last_status = st;
    }
    close_all_slots();

    if (last_status == 200) return 0;
    return last_status ? 0 : 2;
}
