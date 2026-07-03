/* httpsget — Aurora's userspace HTTPS client (14.0.3b / 14.0.4 in QEMU; 15.2
 * adds redirects; 15.4 adds HTTP keep-alive; 15.8 adds a multi-origin
 * session cache; 15.9 adds cookies; 15.10 adds gzip; 16.1 adds HTTP POST;
 * 16.2 adds HTTP authentication; 16.3 makes redirects RFC-correct for a
 * request with a body; 16.4 adds multipart/form-data; 16.5 adds a general
 * --method for HEAD/OPTIONS/DELETE/PUT/PATCH; 17.0 adds ALPN; 17.1.1 adds
 * the HTTP/2 connection-establishment handshake; 17.1.2 adds a generic
 * HTTP/2 frame reader and DATA frame support; 17.1.3 adds a real,
 * HPACK-compressed HEADERS frame that opens a genuine h2 request).
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
 * multipart/form-data (Phase 16.4): `httpsget --post-multipart <host>
 * <path> <field=value | field=@localfile> [...] [now_unix]` encodes each
 * field as its own MIME part behind a generated boundary -- `field=value`
 * is a plain text part, `field=@localfile` reads `localfile` off Aurora's
 * own FAT32 disk (there's no stat/lseek syscall to size it up front, so
 * it's read()  in a loop until EOF or the shared POST_BODY_MAX cap) and
 * sends it as a file part with a fixed application/octet-stream
 * Content-Type. Same shell constraint as --post: every field is its own
 * whitespace-free CLI token, so a field's name or value can't itself
 * contain a space. Follows the same 16.3 redirect rules as a plain POST,
 * just carrying its Content-Type (with the boundary) along for the ride.
 *
 * `--method <VERB>` (Phase 16.5) generalizes what used to be a hardcoded
 * GET-or-POST choice to any of GET/HEAD/OPTIONS/DELETE (no body; `<host>
 * <path> [path...] [now_unix]`, same shape as a plain GET) or POST/PUT/
 * PATCH (one body token; same shape as --post, which is now just this
 * client's older, still-supported spelling of `--method POST`). A HEAD
 * response is handled per RFC 7230 SS3.3.3: its body is always empty no
 * matter what Content-Length claims (that header, if present, describes
 * what a GET would have returned) -- getting this wrong would make a
 * keep-alive HEAD response hang the client forever waiting for body bytes
 * the server was never going to send.
 *
 * ALPN (Phase 17.0, RFC 7301, opening the "modern transport" series that
 * follows the "Web Platform" series above): `--alpn` offers "h2" and
 * "http/1.1" in the TLS ClientHello and prints whatever the server selects.
 * Without --alpn the extension is omitted entirely, byte-identical to every
 * ClientHello before this phase.
 *
 * HTTP/2 connection establishment (Phase 17.1.1, RFC 7540 §3.5/§6.5, the
 * new http2/ directory): once ALPN actually selects h2, `h2_handshake()`
 * sends the 24-byte connection preface and an empty SETTINGS frame, then
 * exchanges SETTINGS/SETTINGS-ACK with the server -- the two frames every
 * HTTP/2 connection is required to trade before anything else can happen.
 * `h2_handshake()`'s own frame reading (Phase 17.1.2) goes through a
 * generic `h2_frame_reader` (reassembling a header or payload split across
 * TLS records, the same job `tls_conn`'s `hs_buf` already does one layer
 * up), so it correctly recognizes -- without necessarily acting on -- any
 * frame type, including a DATA frame the reader knows how to decode the
 * padding-aware payload of (`http2/data.c`).
 *
 * A real request (Phase 17.1.3, `http2/hpack.c` + `http2/headers.c`): once
 * the handshake succeeds, `h2_fetch()` HPACK-compresses :method, :scheme,
 * :authority, :path and a user-agent -- using ONLY RFC 7541's static table
 * (Aurora's own encoder never uses Huffman or the dynamic table; see
 * headers.c/hpack.c's own comments for why) -- into a real HEADERS frame
 * and sends it, opening stream 1.
 *
 * A full HPACK decoder (Phase 17.2.1/17.2.2, `http2/huffman.c` +
 * `http2/hpack_table.c` + `http2/hpack_decode.c`): Huffman decoding (RFC
 * 7541 §5.2/Appendix B), the full 61-entry static table (Appendix A), and a
 * decode-side dynamic table (§2.3.2/§4/§6) tracking whatever a *peer's*
 * encoder does -- independent of Aurora's own send-side static-table-only
 * choice (RFC 7541 §2.3.2 makes the two directions' tables independent).
 * Together these can decode any real HEADERS frame a real server sends,
 * once Phase 17.3 (below) actually calls them on the live response path.
 *
 * The first real HTTP/2 response (Phase 17.3): `h2_fetch()` reads stream 1
 * to completion -- one HEADERS frame (HPACK-decoded via `slot`'s own
 * per-connection dynamic table) optionally followed by DATA frames, until
 * the server's own END_STREAM arrives. The decoded header list is
 * translated into an HTTP/1.1-shaped status-line-plus-headers text block
 * (`h2_synthesize_header_block()`) and fed, together with each DATA
 * frame's payload, through the EXISTING `resp_feed()` -- the same function
 * an HTTP/1.1 response's bytes flow through -- so Set-Cookie parsing, gzip
 * streaming, and `struct http_response` population all just work,
 * unchanged, for an h2 response too. `fetch_one()` itself needed zero
 * changes: it still only ever sees a `fetch_result_t`, never anything
 * protocol-specific. Deliberately still just one stream, no multiplexing,
 * and no PRIORITY/PUSH_PROMISE/CONTINUATION/flow-control handling beyond
 * what's needed to read that one stream -- an h2 connection is always
 * closed after its one response (a synthesized "Connection: close" line
 * makes the existing keep-alive/reuse logic below do that on its own, with
 * no h2-specific code of its own); carrying a request method/body other
 * than GET over h2 is equally out of scope. Both are natural follow-ups,
 * not attempted here.
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
#include "frame.h"
#include "settings.h"
#include "data.h"
#include "hpack.h"
#include "headers.h"
#include "hpack_table.h"
#include "hpack_decode.h"

#define HTTPSGET_NOW 1782864000ULL   /* 2026-07-01; override via a numeric argument */
#define MAX_REDIRECTS 20             /* hop ceiling; visited[] also catches loops earlier */
#define MAX_PATHS     16
#define AUTH_TOKEN_MAX  512          /* raw bearer token or "user:pass" length cap (Phase 16.2) */
#define AUTH_HEADER_MAX (8 + 4 * ((AUTH_TOKEN_MAX + 2) / 3))  /* "Basic "/"Bearer " + base64 worst case */
#define FETCH_REUSE_MAX_BODY (64u * 1024u)  /* don't bother draining a response this big just to reuse the connection */
#define POST_BODY_MAX 4096           /* a diagnostic CLI, not a general uploader (Phase 16.1); shared
                                      * cap for both a plain --post body and an encoded --post-multipart
                                      * body (Phase 16.4) -- one body buffer size, not two */
#define REQ_BUF_MAX   (2048 + POST_BODY_MAX)  /* headers (incl. a full Cookie: line) + body */
#define MULTIPART_FIELDS_MAX 8        /* CLI field cap (Phase 16.4) -- sh.c's ARG_MAX (16) leaves
                                       * little room for more anyway, see tokenize() in user/sh.c */
#define BOUNDARY_MAX          40      /* "AuroraBoundary" + 16 hex digits + NUL, rounded up */
#define MULTIPART_CTYPE_MAX  (32 + BOUNDARY_MAX)  /* "multipart/form-data; boundary=" + boundary */
#define ALPN_PROTOCOL_COUNT 2         /* {"h2", "http/1.1"} -- see g_alpn_protocols (Phase 17.0) */

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

/* HTTP/2 frame reassembly (Phase 17.1.2): one h2_frame_reader (~16 KiB,
 * H2_FRAME_HEADER_LEN + H2_FRAME_PAYLOAD_MAX) is plenty -- like every other
 * scratch buffer in this file, this client never has more than one fetch in
 * flight, so there's never a second h2 handshake/exchange needing its own
 * independent reassembly state at the same time. MUST stay a global for the
 * same reason g_slots/tls_conn/tls_record_reader already are (see the
 * 15.10 stack-overflow postmortem in docs/SECURITY.md) -- never a local. */
static h2_frame_reader   g_h2_reader;

/* h2 response decode scratch (Phase 17.3): sized generously for a real
 * response's header block, not just this project's own test vectors --
 * H2_HEADER_FIELDS_MAX distinct fields, H2_HPACK_SCRATCH_MAX bytes of
 * decoded (Huffman-expanded or literal) name/value text. Global for the
 * same reason g_h2_reader is: this client never has more than one fetch in
 * flight, so there's never a second h2 response decode needing its own
 * independent scratch space at the same time (see the 15.10 stack-overflow
 * postmortem in docs/SECURITY.md for why that discipline matters here). */
#define H2_HEADER_FIELDS_MAX 48
#define H2_HPACK_SCRATCH_MAX 4096
static uint8_t            g_h2_hpack_scratch[H2_HPACK_SCRATCH_MAX];
static hpack_header_field  g_h2_fields[H2_HEADER_FIELDS_MAX];

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

/* multipart/form-data (Phase 16.4): the encoded body and its Content-Type
 * (which carries the boundary) are built once in main() from
 * --post-multipart's CLI fields, then handed down through fetch_one()
 * exactly like a plain --post body -- fetch_one()/fetch()/fetch_request()/
 * build_request() never need to know a body is multipart-shaped, only that
 * it comes with a caller-supplied Content-Type instead of the default
 * url-encoded one. */
static uint8_t     g_multipart_body[POST_BODY_MAX];
static char        g_boundary[BOUNDARY_MAX];
static char        g_multipart_ctype[MULTIPART_CTYPE_MAX];

/* ALPN (Phase 17.0, RFC 7301): opt-in via --alpn, offered fresh on every new
 * TLS connection (fetch_begin()) for the whole run -- there's no per-request
 * variability to it, unlike Authorization/Cookie. "h2" is listed first only
 * because that's the point of demonstrating a real choice between two
 * options; Aurora doesn't speak HTTP/2 yet, so fetch_begin() refuses to
 * continue a connection where the server actually picked it (see its own
 * comment) rather than pretending nothing happened. */
static const char *g_alpn_protocols[ALPN_PROTOCOL_COUNT] = { "h2", "http/1.1" };
static int         g_alpn_enabled;

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
    int         is_h2;        /* Phase 17.3: this connection negotiated h2 over ALPN and
                               * completed the connection-establishment handshake -- always
                               * freshly determined by fetch_begin() at the top of every call,
                               * never needs resetting in slot_find_or_alloc() too. */
    hpack_dyn_table h2_dyn_table;   /* this h2 connection's decode-side HPACK compression
                                     * context (RFC 7541 §2.3.2) -- re-initialized by
                                     * fetch_begin() every time a fresh h2 connection is
                                     * established, since a new TCP connection always starts
                                     * a new compression context with nothing carried over. */
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
 * handshake.
 *
 * `req_method` (Phase 16.5) matters because a HEAD response's Content-Length,
 * if present, describes what a GET would have returned, not what actually
 * came down the wire (RFC 7230 SS3.3.3) -- a real body of zero bytes always
 * follows a HEAD response no matter how large that header claims, so it's
 * always safe to reuse a keep-alive HEAD response's connection regardless of
 * FETCH_REUSE_MAX_BODY. */
static int reusable(const struct http_response *hr, const char *req_method)
{
    unsigned effective_len = strcmp(req_method, "HEAD") == 0 ? 0 : (unsigned)hr->content_length;
    return hr->keep_alive && effective_len <= FETCH_REUSE_MAX_BODY;
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
 * request); when present, `content_type` (Phase 16.4) says what Content-Type
 * to send with them -- NULL defaults to application/x-www-form-urlencoded,
 * the one body shape a plain --post's CLI can actually construct (a single
 * whitespace-free token; Aurora's shell has no quoting, see main());
 * --post-multipart instead passes its own "multipart/form-data;
 * boundary=..." value.
 *
 * `auth_header`/`auth_len` (Phase 16.2) are an optional pre-built
 * Authorization value ("Basic <base64>" or "Bearer <token>"; NULL/0 for
 * none) -- the caller (fetch_one()) decides per-hop whether this request's
 * origin still matches the one credentials were given for. */
static void build_request(char *req, int *rn, const struct url *u, uint64_t now,
                          const char *method, const uint8_t *body, int bodylen,
                          const char *content_type,
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
        app(req, rn, "Content-Type: ");
        app(req, rn, content_type ? content_type : "application/x-www-form-urlencoded");
        app(req, rn, "\r\nContent-Length: ");
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
static int  g_no_body;            /* Phase 16.5: true for the response to a HEAD request -- RFC 7230
                                   * SS3.3.3 rule 1 says a HEAD response body is ALWAYS empty regardless
                                   * of what its Content-Length claims (that header, if present, describes
                                   * what a GET to the same resource would have returned); without this,
                                   * a keep-alive HEAD response advertising a nonzero Content-Length would
                                   * make the read loop below wait forever for body bytes the server is
                                   * never going to send. */
static const char *g_cur_method;  /* this exchange's request method, for reusable()'s own HEAD check below */
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

static void resp_reset(const char *req_method)
{
    g_rlen = 0; g_total = 0; g_hdrs_done = 0; g_target = -1;
    g_no_body = strcmp(req_method, "HEAD") == 0;
    g_cur_method = req_method;
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
            if (g_no_body)
                g_target = g_hr.header_len;   /* HEAD: no body at all, whatever Content-Length says */
            else if (reusable(&g_hr, g_cur_method))
                g_target = g_hr.header_len + g_hr.content_length;   /* drain exactly to the boundary */
            if (g_hr.gzip && !g_hr.chunked && !g_no_body) {
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

#define H2_HANDSHAKE_FRAME_CAP 64   /* safety cap against a pathological/buggy peer never
                                     * sending the two frames this is waiting for -- the
                                     * same role MAX_REDIRECTS plays elsewhere in this file */
#define H2_RESPONSE_FRAME_CAP 256  /* looser than H2_HANDSHAKE_FRAME_CAP -- a real response
                                    * body can legitimately take many more read()s/frames
                                    * than the two-frame handshake ever needs */

/* Exact (case-sensitive) match -- RFC 7540 §8.1.2 requires an h2 peer to
 * send header field names already lowercased, so this never needs to be
 * case-insensitive the way http.c's own ci_starts() has to be for
 * HTTP/1.1's looser wire format. */
static int eq_bytes(const uint8_t *a, size_t alen, const char *b)
{
    size_t i = 0;
    for (; b[i]; i++) if (i >= alen || a[i] != (uint8_t)b[i]) return 0;
    return i == alen;
}

/* True if `s[0..len)` is safe to splice verbatim into a synthesized
 * "name: value\r\n" HTTP/1.1-style header line -- i.e. contains neither CR
 * nor LF (which would let a malicious HPACK-encoded value inject an extra
 * header line, or corrupt the synthesized blank-line boundary -- the HTTP
 * response-splitting equivalent for this translation step) nor, for a
 * header NAME specifically, a ':' (RFC 7230 token syntax: a field-name can
 * never legitimately contain one). Aurora's own HPACK decoder (http2/
 * hpack_decode.c) doesn't enforce field-name/value syntax -- it only knows
 * how to decode bytes, not validate HTTP semantics -- so this is the
 * boundary where untrusted wire content actually gets checked before it's
 * trusted enough to reuse http.c's HTTP/1.1 text parser on. */
static int h2_text_safe(const uint8_t *s, size_t len, int is_name)
{
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\r' || s[i] == '\n') return 0;
        if (is_name && s[i] == ':') return 0;
    }
    return 1;
}

/* Translate one decoded HPACK header field list (RFC 7541) for an h2
 * response into an HTTP/1.1-shaped status-line-plus-headers text block --
 * so the EXISTING http_parse()-based pipeline below (resp_feed(), Set-
 * Cookie enumeration via http_find_header(), gzip/content-type/location
 * detection, body-preview printing in fetch_one()) can consume an h2
 * response exactly like an HTTP/1.1 one. This is Phase 17.3's whole
 * point: the upper layer never needs a separate "HTTP/2 response" shape,
 * or even to know which wire protocol actually carried the response.
 *
 * Requires exactly one ":status" pseudo-header, a 3-digit value, and no
 * other pseudo-header (a conformant HTTP/2 response never sends one --
 * RFC 7540 §8.1.2.4). Every other decoded field becomes one "name:
 * value\r\n" line verbatim (after h2_text_safe() clears it), EXCEPT the
 * handful of HTTP/1.1 connection-specific headers RFC 7540 §8.1.2.2
 * forbids sending over h2 at all (connection, transfer-encoding,
 * keep-alive, upgrade) -- skipped rather than trusted, since forwarding
 * one from a nonconformant peer could desync the reused chunked/keep-alive
 * logic downstream. A synthesized "Connection: close" line is always
 * appended instead, so http_parse()'s own keep-alive computation (reused
 * completely unchanged) naturally comes out false -- Phase 17.3
 * deliberately doesn't reuse an h2 connection for a second stream/request
 * (see docs/SECURITY.md, Step 17.3), and this one line is what makes the
 * EXISTING reusable()/slot_close() logic in fetch()/fetch_one() already do
 * the right thing with no h2-specific code of its own.
 *
 * Returns the header block's length (including the trailing blank line),
 * or -1 if it wouldn't fit `cap`, :status is missing/duplicated/
 * non-3-digit, an unexpected pseudo-header appears, or any name/value
 * fails h2_text_safe(). */
static int h2_synthesize_header_block(char *out, int cap, const hpack_header_field *fields, size_t count)
{
    if (cap < 64) return -1;   /* room for the fixed-shape status line + "Connection: close" trailer below */

    int status = -1;
    for (size_t i = 0; i < count; i++) {
        if (fields[i].name_len == 0 || fields[i].name[0] != ':') continue;
        if (!eq_bytes(fields[i].name, fields[i].name_len, ":status")) return -1;   /* unexpected pseudo-header */
        if (status >= 0) return -1;                                              /* duplicate :status */
        if (fields[i].value_len != 3) return -1;
        int v = 0;
        for (int k = 0; k < 3; k++) {
            uint8_t c = fields[i].value[k];
            if (c < '0' || c > '9') return -1;
            v = v * 10 + (c - '0');
        }
        status = v;
    }
    if (status < 0) return -1;   /* no :status pseudo-header at all */

    int n = 0;
    app(out, &n, "HTTP/1.1 ");
    app_uint(out, &n, (unsigned)status);
    app(out, &n, " (via HTTP/2)\r\n");

    for (size_t i = 0; i < count; i++) {
        if (fields[i].name_len > 0 && fields[i].name[0] == ':') continue;   /* :status already handled */
        if (!h2_text_safe(fields[i].name, fields[i].name_len, 1) || !h2_text_safe(fields[i].value, fields[i].value_len, 0))
            return -1;
        if (eq_bytes(fields[i].name, fields[i].name_len, "connection") ||
            eq_bytes(fields[i].name, fields[i].name_len, "transfer-encoding") ||
            eq_bytes(fields[i].name, fields[i].name_len, "keep-alive") ||
            eq_bytes(fields[i].name, fields[i].name_len, "upgrade"))
            continue;

        if (n + (int)fields[i].name_len + (int)fields[i].value_len + 4 >= cap) return -1;
        for (size_t k = 0; k < fields[i].name_len; k++) out[n++] = (char)fields[i].name[k];
        out[n++] = ':'; out[n++] = ' ';
        for (size_t k = 0; k < fields[i].value_len; k++) out[n++] = (char)fields[i].value[k];
        out[n++] = '\r'; out[n++] = '\n';
    }

    if (n + 20 >= cap) return -1;
    app(out, &n, "Connection: close\r\n\r\n");
    return n;
}

/* Send stream 1's request (Phase 17.1.3's h2_send_request(), extended) and
 * this time actually read the full response -- Phase 17.3. Always a GET to
 * u->host/u->path: carrying an arbitrary method/body over h2 is explicitly
 * out of this phase's scope (see docs/SECURITY.md, Step 17.3), the same way
 * it always has been for this h2 code path.
 *
 * Reads frames on stream 1 until the server's own END_STREAM arrives (on a
 * body-less HEADERS, or the final DATA frame) or the connection closes.
 * HEADERS is HPACK-decoded (`slot`'s own persistent dynamic table, so a
 * peer using "Literal with Incremental Indexing" or an indexed dynamic
 * entry works correctly) and translated via h2_synthesize_header_block()
 * into an HTTP/1.1-shaped text block fed through the EXISTING resp_feed()
 * -- so Set-Cookie parsing, gzip streaming, and Content-Type/Location
 * detection all just work, unchanged, for an h2 response too. DATA frame
 * payloads (padding-aware, via h2_data_parse()) are fed through resp_feed()
 * the same way. This is deliberately still just ONE client stream, never
 * multiplexed, with no PRIORITY/PUSH_PROMISE/CONTINUATION/flow-control
 * handling beyond what's needed to read one stream to completion --
 * "HTTP/2 v2" territory this phase intentionally leaves alone.
 *
 * Fills g_hr/g_resp/g_body exactly like the HTTP/1.1 path's own read loop
 * does (via the same resp_feed()), but does NOT fill `out` itself or scan
 * for Set-Cookie -- that's fetch_request()'s shared tail, run for this
 * path too, so an h2 response's cookies are stored exactly the same way
 * an HTTP/1.1 response's are, with no separate code path of its own.
 *
 * Returns 1 if the server's own END_STREAM arrived (a definitive "this
 * response is complete" signal, the h2 equivalent of an HTTP/1.1
 * connection closing cleanly), 0 if the connection closed first without
 * one, or -1 on any protocol/transport failure or malformed HPACK (a
 * diagnostic has already been printed in every case; per hpack_decode.h's
 * own contract, a malformed header block is unrecoverable for the rest of
 * this connection, so -1 here always means "give up on it entirely," not
 * "retry this one request"). */
static int h2_fetch(session_slot *slot, const struct url *u)
{
    resp_reset("GET");

    static const char *ua = "Aurora-httpsget/0.3";
    uint8_t hdrbuf[1024];
    int hn = h2_build_headers(hdrbuf, sizeof hdrbuf, 1,
                              "GET", (size_t)strlen("GET"),
                              u->host, (size_t)strlen(u->host),
                              u->path, (size_t)strlen(u->path),
                              ua, (size_t)strlen(ua));
    if (hn < 0) { fprintf(2, "[httpsget] h2: could not build the HEADERS frame\n"); return -1; }

    int sl = tls_conn_send_app(&slot->conn, hdrbuf, (size_t)hn, g_scratch, sizeof g_scratch);
    if (sl < 0) { fprintf(2, "[httpsget] h2: could not seal the HEADERS frame\n"); return -1; }
    if (write_all(slot->fd, g_scratch, sl) != 0) { fprintf(2, "[httpsget] h2: write failed\n"); return -1; }
    printf("[httpsget] h2: HEADERS frame sent (stream 1, GET %s)\n", u->path);

    h2_frame_reader_init(&g_h2_reader);
    int got_headers = 0, stream_ended = 0;

    for (int reads = 0; !stream_ended && reads < H2_RESPONSE_FRAME_CAP; reads++) {
        const uint8_t *rec; size_t rl; int cc;
        while (!stream_ended && (cc = tls_reader_next(&slot->reader, &rec, &rl)) == 1) {
            size_t pl = 0;
            int rr = tls_conn_recv_app(&slot->conn, rec, rl, g_plain, sizeof g_plain, &pl);
            if (rr == TLS_CONN_ERR_ALERT || rr < 0) { stream_ended = 1; break; }

            size_t pos = 0;
            while (!stream_ended && pos < pl) {
                int fed = h2_frame_reader_feed(&g_h2_reader, g_plain + pos, pl - pos);
                if (fed < 0) { fprintf(2, "[httpsget] h2: response frame too large (frame size error)\n"); return -1; }
                pos += (size_t)fed;

                h2_frame_header fh; const uint8_t *payload; size_t payload_len;
                while (h2_frame_reader_next(&g_h2_reader, &fh, &payload, &payload_len) == 1) {
                    if (fh.type == H2_TYPE_GOAWAY) {
                        fprintf(2, "[httpsget] h2: server sent GOAWAY while reading the response\n");
                        return -1;
                    }
                    if (fh.stream_id != 1) continue;   /* not our stream -- irrelevant */
                    if (fh.type == H2_TYPE_RST_STREAM) {
                        fprintf(2, "[httpsget] h2: server reset stream 1\n");
                        return -1;
                    }

                    if (fh.type == H2_TYPE_HEADERS) {
                        if (got_headers) {
                            fprintf(2, "[httpsget] h2: a second HEADERS on stream 1 (trailers) is not supported\n");
                            return -1;
                        }
                        if (!(fh.flags & H2_FLAG_END_HEADERS)) {
                            fprintf(2, "[httpsget] h2: HEADERS without END_HEADERS (CONTINUATION is not supported)\n");
                            return -1;
                        }
                        size_t nfields, scratch_used;
                        if (hpack_decode_headers(payload, payload_len, &slot->h2_dyn_table,
                                                 g_h2_fields, H2_HEADER_FIELDS_MAX, &nfields,
                                                 g_h2_hpack_scratch, sizeof g_h2_hpack_scratch, &scratch_used) != 0) {
                            fprintf(2, "[httpsget] h2: HPACK decode failed (malformed or unsupported header block)\n");
                            return -1;
                        }
                        char hdrtext[4096];
                        int htn = h2_synthesize_header_block(hdrtext, sizeof hdrtext, g_h2_fields, nfields);
                        if (htn < 0) { fprintf(2, "[httpsget] h2: could not translate the decoded response headers\n"); return -1; }
                        got_headers = 1;
                        printf("[httpsget] h2: HEADERS decoded (%u header fields)\n", (unsigned)nfields);
                        resp_feed((const uint8_t*)hdrtext, htn);
                        if (fh.flags & H2_FLAG_END_STREAM) stream_ended = 1;
                    } else if (fh.type == H2_TYPE_DATA) {
                        if (!got_headers) { fprintf(2, "[httpsget] h2: DATA before HEADERS on stream 1\n"); return -1; }
                        const uint8_t *data; size_t data_len;
                        if (h2_data_parse(payload, payload_len, fh.flags, &data, &data_len) != 0) {
                            fprintf(2, "[httpsget] h2: malformed DATA frame\n"); return -1;
                        }
                        resp_feed(data, (int)data_len);
                        if (fh.flags & H2_FLAG_END_STREAM) stream_ended = 1;
                    }
                    /* anything else on our stream (WINDOW_UPDATE, PRIORITY, ...)
                     * is silently skipped -- 17.3's deliberately minimal scope. */
                    if (stream_ended) break;
                }
            }
        }
        if (stream_ended) break;
        if (cc < 0) { fprintf(2, "[httpsget] h2: malformed TLS record while reading the response\n"); return -1; }
        int rn = read(slot->fd, g_scratch, sizeof g_scratch);
        if (rn <= 0) break;   /* connection closed -- treat whatever arrived as the final response */
        tls_reader_feed(&slot->reader, g_scratch, (size_t)rn);
    }

    if (!got_headers) { fprintf(2, "[httpsget] h2: connection closed before any response headers arrived\n"); return -1; }
    printf("[httpsget] h2: stream 1 complete (status=%d, %d body bytes)\n", g_hr.status, g_total - g_hr.header_len);
    return stream_ended;
}

/* Complete the mandatory HTTP/2 connection-establishment handshake (RFC
 * 7540 §3.5/§6.5), Phase 17.1.1, once ALPN (17.0) has selected "h2": send
 * the connection preface followed by an empty SETTINGS frame, then read
 * frames -- via the generic h2_frame_reader (Phase 17.1.2), which handles a
 * frame header or payload arriving split across TLS records the same way
 * tls_conn's own hs_buf already does one layer up -- until both the
 * server's own SETTINGS (acknowledged immediately, as §6.5 requires) and a
 * SETTINGS ACK for ours have arrived. Their relative order isn't guaranteed
 * by the spec and real servers differ, so both are watched for
 * independently rather than assuming one comes before the other. Any other
 * frame type seen in between (a connection-level WINDOW_UPDATE right after
 * SETTINGS is common in practice, and so, now that streams exist as a
 * concept the reader recognizes even though nothing opens one yet, is a
 * stray DATA frame) is skipped, not rejected -- this handshake only cares
 * about the two frames it's actually waiting for, the same "skip what
 * you don't understand yet" posture 17.0 already established for
 * EncryptedExtensions. A GOAWAY means the server is refusing the
 * connection outright and ends the attempt immediately, since nothing
 * being waited for is ever coming after that.
 *
 * Phase 17.1.2 still stops here: there is no HEADERS framing yet, so even a
 * successful return doesn't mean a request can actually be sent -- see the
 * caller (fetch_begin()), which still refuses to proceed to an actual
 * fetch either way, now backed by a genuine verified h2 connection instead
 * of an outright ALPN-result refusal.
 *
 * Returns 0 if the handshake itself completed, -1 on any protocol/
 * transport failure or if the frame cap is hit (a diagnostic has already
 * been printed in every case). */
static int h2_handshake(session_slot *slot)
{
    uint8_t plaintext[H2_PREFACE_LEN + H2_FRAME_HEADER_LEN];
    int n = 0;
    memcpy(plaintext, H2_PREFACE, H2_PREFACE_LEN); n += H2_PREFACE_LEN;
    int sn = h2_build_settings_empty(plaintext + n, sizeof plaintext - (size_t)n);
    if (sn < 0) { fprintf(2, "[httpsget] h2: could not build the initial SETTINGS frame\n"); return -1; }
    n += sn;

    int sl = tls_conn_send_app(&slot->conn, plaintext, (size_t)n, g_scratch, sizeof g_scratch);
    if (sl < 0) { fprintf(2, "[httpsget] h2: could not seal the preface+SETTINGS\n"); return -1; }
    if (write_all(slot->fd, g_scratch, sl) != 0) { fprintf(2, "[httpsget] h2: write failed\n"); return -1; }
    printf("[httpsget] h2: connection preface + SETTINGS sent\n");

    h2_frame_reader_init(&g_h2_reader);
    int got_server_settings = 0, got_settings_ack = 0, frames_seen = 0;

    while (!(got_server_settings && got_settings_ack)) {
        const uint8_t *rec; size_t rl; int cc;
        while ((cc = tls_reader_next(&slot->reader, &rec, &rl)) == 1) {
            size_t pl = 0;
            int rr = tls_conn_recv_app(&slot->conn, rec, rl, g_plain, sizeof g_plain, &pl);
            if (rr == TLS_CONN_ERR_ALERT) { fprintf(2, "[httpsget] h2: peer sent a TLS alert\n"); return -1; }
            if (rr < 0) { fprintf(2, "[httpsget] h2: recv_app error %d\n", rr); return -1; }

            size_t pos = 0;
            while (pos < pl) {
                int fed = h2_frame_reader_feed(&g_h2_reader, g_plain + pos, pl - pos);
                if (fed < 0) { fprintf(2, "[httpsget] h2: frame too large (frame size error)\n"); return -1; }
                pos += (size_t)fed;

                h2_frame_header fh; const uint8_t *payload; size_t payload_len;
                while (h2_frame_reader_next(&g_h2_reader, &fh, &payload, &payload_len) == 1) {
                    if (++frames_seen > H2_HANDSHAKE_FRAME_CAP) {
                        fprintf(2, "[httpsget] h2: gave up waiting for SETTINGS/ACK after %d frames\n", frames_seen);
                        return -1;
                    }

                    if (fh.type == H2_TYPE_GOAWAY) {
                        fprintf(2, "[httpsget] h2: server sent GOAWAY -- refusing this connection\n");
                        return -1;
                    } else if (h2_is_settings_ack(&fh)) {
                        if (fh.length != 0) { fprintf(2, "[httpsget] h2: malformed SETTINGS ACK (nonzero length)\n"); return -1; }
                        got_settings_ack = 1;
                        printf("[httpsget] h2: our SETTINGS was ACKed\n");
                    } else if (fh.type == H2_TYPE_SETTINGS) {
                        if (!h2_settings_payload_valid(fh.length)) { fprintf(2, "[httpsget] h2: malformed SETTINGS frame\n"); return -1; }
                        got_server_settings = 1;
                        printf("[httpsget] h2: server SETTINGS received (%u bytes)\n", (unsigned)fh.length);

                        uint8_t ack[H2_FRAME_HEADER_LEN];
                        int an = h2_build_settings_ack(ack, sizeof ack);
                        int asl = tls_conn_send_app(&slot->conn, ack, (size_t)an, g_scratch, sizeof g_scratch);
                        if (asl < 0 || write_all(slot->fd, g_scratch, asl) != 0) {
                            fprintf(2, "[httpsget] h2: could not send our SETTINGS ACK\n"); return -1;
                        }
                        printf("[httpsget] h2: SETTINGS ACK sent\n");
                    } else if (fh.type == H2_TYPE_DATA) {
                        /* No stream is open yet (HEADERS -- a later phase -- is what
                         * would open one), so there's nothing to do with this beyond
                         * recognizing it correctly; (void) keeps an unused-but-
                         * intentionally-decoded variable from warning. */
                        (void)payload;
                        printf("[httpsget] h2: DATA frame seen (stream %u, %u bytes) -- ignored, no open stream yet\n",
                               (unsigned)fh.stream_id, (unsigned)payload_len);
                    }
                    /* anything else (WINDOW_UPDATE, PING, PRIORITY, ...) is silently
                     * skipped -- not one of the frames this handshake is waiting for. */
                }
            }
        }
        if (cc < 0) { fprintf(2, "[httpsget] h2: malformed TLS record\n"); return -1; }
        if (got_server_settings && got_settings_ack) break;
        int rn = read(slot->fd, g_scratch, sizeof g_scratch);
        if (rn <= 0) { fprintf(2, "[httpsget] h2: connection closed before the handshake completed\n"); return -1; }
        tls_reader_feed(&slot->reader, g_scratch, (size_t)rn);
    }
    printf("[httpsget] h2: connection-establishment handshake complete\n");
    return 0;
}

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

    slot->is_h2 = 0;   /* freshly determined by THIS connection attempt every time --
                        * whatever a slot's previous, possibly-different-origin connection
                        * negotiated never carries over */

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
        if (g_alpn_enabled)
            tls_conn_offer_alpn(&slot->conn, g_alpn_protocols, ALPN_PROTOCOL_COUNT);

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
        if (g_alpn_enabled) {
            if (slot->conn.fsm.alpn_negotiated) {
                printf("[TLS] ALPN negotiated: %s\n", slot->conn.fsm.alpn_selected);
                if (strcmp(slot->conn.fsm.alpn_selected, "h2") == 0) {
                    /* Phase 17.3: once the connection-establishment handshake
                     * completes, this connection is ready to carry a real h2
                     * request/response -- h2_fetch() (called from
                     * fetch_request() below, mirroring exactly how the
                     * HTTP/1.1 path only sends+reads there too) does the
                     * rest. Continuing to speak HTTP/1.1 over a connection
                     * the server now expects to carry HTTP/2 framing would
                     * just hang or desync, not degrade gracefully -- so a
                     * failed handshake here still aborts the connection
                     * attempt outright, same as every phase before this one. */
                    if (h2_handshake(slot) != 0) { close(slot->fd); return -1; }
                    hpack_table_init(&slot->h2_dyn_table, HPACK_DYN_ARENA_SIZE);
                    slot->is_h2 = 1;
                }
            } else {
                printf("[TLS] ALPN: no protocol selected by the server\n");
            }
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
                         const char *method, const uint8_t *body, int bodylen, const char *content_type,
                         const char *auth_header, int auth_len, fetch_result_t *out)
{
    int closed = 0;

    /* Phase 17.3: an h2-negotiated connection speaks HTTP/2 framing, not
     * HTTP/1.1 request-line text -- h2_fetch() is this branch's entire
     * request+response cycle (always a GET, see its own comment for why).
     * It fills g_hr/g_resp/g_body via the same resp_feed() the HTTP/1.1
     * path below uses, so the shared tail after this if/else (staleness
     * check, Set-Cookie scan, *out fill) applies unchanged to an h2
     * response too -- the caller (fetch()/fetch_one()) never needs to know
     * which path actually ran. `method`/`body`/`bodylen`/`content_type`/
     * `auth_header`/`auth_len` are intentionally unused here -- carrying
     * them over h2 is out of this phase's scope. */
    if (slot->origin.https && slot->is_h2) {
        int rc = h2_fetch(slot, u);
        if (rc < 0) return -1;
        closed = rc;
    } else {
        resp_reset(method);
        char req[REQ_BUF_MAX]; int rn;
        build_request(req, &rn, u, now, method, body, bodylen, content_type, auth_header, auth_len);

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
                 const uint8_t *body, int bodylen, const char *content_type,
                 const char *auth_header, int auth_len, fetch_result_t *out)
{
    session_slot *slot = slot_find_or_alloc(u);
    if (slot->conn_open) {
        printf("[httpsget] reusing open connection to %s:%d (keep-alive)\n", u->host, u->port);
        int rc = fetch_request(slot, u, now, method, body, bodylen, content_type, auth_header, auth_len, out);
        if (rc == FETCH_OK) return 0;
        if (rc != FETCH_STALE) return -1;
        printf("[httpsget] reused connection to %s:%d was already closed -- reconnecting\n", u->host, u->port);
        slot_close(slot);
    }
    if (fetch_begin(slot, u, now) != 0) return -1;
    int rc = fetch_request(slot, u, now, method, body, bodylen, content_type, auth_header, auth_len, out);
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
 * `method`/`post_body`/`post_bodylen`/`content_type` (Phase 16.1, extended
 * 16.4 to also carry a caller-supplied Content-Type alongside the body)
 * start as given for the first request (hop 0) and are then re-decided
 * after every redirect response, per RFC 7231/7238 (Phase 16.3): 307 and
 * 308 preserve the current method, body and Content-Type unchanged onto the
 * next hop, while every other redirect status (301/302/303) downgrades to
 * a bodyless GET, matching what browsers have done since long before it
 * was standardized. */
static int fetch_one(const char *host, const char *path, uint64_t now, const char *label,
                     const char *method, const uint8_t *post_body, int post_bodylen, const char *content_type)
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
    const char *req_content_type = content_type;

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
        if (fetch(&u, now, req_method, req_body, req_bodylen, req_content_type, cur_auth, cur_auth_len, &fr) != 0)
            return -1;    /* diagnostic already printed */
        /* Only this response's own slot closes -- a redirect to a different
         * origin (Phase 15.8) leaves every other origin's slot exactly as it
         * was, so a later hop back to one of them can still reuse it. */
        if (!reusable(&fr.hr, req_method)) slot_close(slot_find_or_alloc(&u));

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
        if (st != 307 && st != 308) { req_method = "GET"; req_body = 0; req_bodylen = 0; req_content_type = 0; }
        u = next;
        hop++;
    }
}

/* Non-cryptographic multipart boundary (Phase 16.4): only needs to be
 * unlikely to collide with a field's own text, nowhere near the strength
 * TLS needs -- reuses fetch_begin()'s own perf_us()^getpid() LCG pattern
 * (see its comment; still NOT suitable for anything security-sensitive)
 * with a different salt so the two streams don't line up. */
static void gen_boundary(char *out, int cap)
{
    static const char *prefix = "AuroraBoundary";
    static const char *hex = "0123456789abcdef";
    unsigned seed = perf_us() ^ (unsigned)getpid() ^ 0x5A5A5A5Au;
    int n = 0;
    for (int i = 0; prefix[i] && n < cap - 1; i++) out[n++] = prefix[i];
    for (int i = 0; i < 16 && n < cap - 1; i++) {
        seed = seed * 1103515245u + 12345u;
        out[n++] = hex[(seed >> 16) & 0xF];
    }
    out[n] = 0;
}

/* Bounds-checked append into a multipart body buffer -- every write against
 * `out`/`outcap` goes through this (Phase 16.4), so there's no intermediate
 * fixed-size header buffer of its own that a long field name or filename
 * could overflow independently of the real body cap. */
static int mp_app(uint8_t *out, int *n, int outcap, const char *s)
{
    int len = (int)strlen(s);
    if (*n + len > outcap) return -1;
    memcpy(out + *n, s, (size_t)len);
    *n += len;
    return 0;
}

/* Encode --post-multipart's fields into `out` as a multipart/form-data body
 * (RFC 2388/7578), returning the encoded length or -1 if it doesn't fit in
 * `outcap` or a file field couldn't be opened (a diagnostic already printed
 * for the latter). Each entry in `fields` is one CLI token "name=value"
 * (mutated in place at '=', the same trick user/sh.c's own tokenize() uses
 * on the raw line); a value starting with '@' is instead a path to read
 * from disk -- there's no stat/lseek syscall to size a file up front, so
 * it's just read() in a loop until EOF or `outcap` is reached, sent with
 * the path's last component as its filename and a fixed
 * application/octet-stream Content-Type (this client doesn't guess a type
 * from the extension -- a diagnostic CLI, not a general uploader, see
 * POST_BODY_MAX). */
static int build_multipart_body(char **fields, int nfields, const char *boundary,
                                uint8_t *out, int outcap)
{
    int n = 0;
    for (int i = 0; i < nfields; i++) {
        char *eq = 0;
        for (char *p = fields[i]; *p; p++) if (*p == '=') { eq = p; break; }
        if (!eq) continue;   /* main() only ever passes tokens containing '=' -- defensive only */
        *eq = 0;
        const char *name = fields[i];
        const char *value = eq + 1;

        if (mp_app(out, &n, outcap, "--") < 0 || mp_app(out, &n, outcap, boundary) < 0 ||
            mp_app(out, &n, outcap, "\r\n") < 0) return -1;

        if (value[0] == '@') {
            const char *path = value + 1;
            const char *base = path;
            for (const char *p = path; *p; p++) if (*p == '/') base = p + 1;

            if (mp_app(out, &n, outcap, "Content-Disposition: form-data; name=\"") < 0 ||
                mp_app(out, &n, outcap, name) < 0 ||
                mp_app(out, &n, outcap, "\"; filename=\"") < 0 ||
                mp_app(out, &n, outcap, base) < 0 ||
                mp_app(out, &n, outcap, "\"\r\nContent-Type: application/octet-stream\r\n\r\n") < 0)
                return -1;

            int fd = open(path, 0);
            if (fd < 0) { fprintf(2, "httpsget: --post-multipart: could not open '%s'\n", path); return -1; }
            for (;;) {
                int cap = outcap - n;
                if (cap <= 0) { close(fd); return -1; }
                int want = cap < 512 ? cap : 512;
                int r = read(fd, out + n, want);
                if (r <= 0) break;
                n += r;
            }
            close(fd);
        } else {
            if (mp_app(out, &n, outcap, "Content-Disposition: form-data; name=\"") < 0 ||
                mp_app(out, &n, outcap, name) < 0 ||
                mp_app(out, &n, outcap, "\"\r\n\r\n") < 0 ||
                mp_app(out, &n, outcap, value) < 0)
                return -1;
        }
        if (mp_app(out, &n, outcap, "\r\n") < 0) return -1;
    }
    if (mp_app(out, &n, outcap, "--") < 0 || mp_app(out, &n, outcap, boundary) < 0 ||
        mp_app(out, &n, outcap, "--\r\n") < 0) return -1;
    return n;
}

/* Every method --method will accept (Phase 16.5), and whether it carries a
 * request body -- GET/POST were the only two methods this client ever sent
 * before this phase, hardcoded throughout; making that a table instead
 * means the CLI, not the fetch pipeline, is what "knows" the method list.
 * build_request()/fetch_request()/fetch()/fetch_one() already took `method`
 * as a plain string with no special-casing beyond this table's callers, so
 * none of them needed to change at all to gain PUT/PATCH/DELETE/HEAD/
 * OPTIONS support. */
typedef struct { const char *name; int body_bearing; } http_method_info_t;
static const http_method_info_t KNOWN_METHODS[] = {
    { "GET",     0 },
    { "HEAD",    0 },
    { "OPTIONS", 0 },
    { "DELETE",  0 },
    { "POST",    1 },
    { "PUT",     1 },
    { "PATCH",   1 },
};
#define KNOWN_METHODS_N (sizeof(KNOWN_METHODS) / sizeof(KNOWN_METHODS[0]))

/* Exact (case-sensitive, matching HTTP's own wire convention) match against
 * KNOWN_METHODS, returning the table's own copy of the name or NULL if
 * `m` isn't one of them. */
static const char *method_lookup(const char *m)
{
    for (unsigned i = 0; i < KNOWN_METHODS_N; i++)
        if (strcmp(m, KNOWN_METHODS[i].name) == 0) return KNOWN_METHODS[i].name;
    return 0;
}

/* Does this method carry a request body? Every `method` value reaching this
 * function came from either a fixed literal already in KNOWN_METHODS ("GET"
 * default, "POST" via --post/--post-multipart) or method_lookup() itself
 * (via --method), so the "unreachable" fallback never actually triggers. */
static int method_body_bearing(const char *m)
{
    for (unsigned i = 0; i < KNOWN_METHODS_N; i++)
        if (strcmp(m, KNOWN_METHODS[i].name) == 0) return KNOWN_METHODS[i].body_bearing;
    return 0;
}

int main(int argc, char **argv)
{
    const char *usage =
        "usage: httpsget [--alpn] [--post] [--auth-basic user:pass | --auth-bearer token]\n"
        "                <host> <path> [path...] [now_unix]\n"
        "       httpsget [--alpn] [--auth-basic user:pass | --auth-bearer token] --post <host> <path> <body> [now_unix]\n"
        "       httpsget [--alpn] [--auth-basic user:pass | --auth-bearer token] --post-multipart <host> <path>\n"
        "                <field=value | field=@localfile> [...] [now_unix]\n"
        "       httpsget [--alpn] [--auth-basic user:pass | --auth-bearer token] --method <GET|HEAD|OPTIONS|DELETE>\n"
        "                <host> <path> [path...] [now_unix]\n"
        "       httpsget [--alpn] [--auth-basic user:pass | --auth-bearer token] --method <POST|PUT|PATCH>\n"
        "                <host> <path> <body> [now_unix]\n";
    const char *method = "GET";
    const uint8_t *post_body = 0;
    int post_bodylen = 0;
    const char *content_type = 0;
    int is_multipart = 0;
    int argi = 1;

    /* Leading flags, any order: --post, --post-multipart (Phase 16.4), or
     * --method (Phase 16.5) -- --post is just --method POST's older, still-
     * supported spelling, kept because existing scripts (and this client's
     * own regression suite) already use it -- and at most one of
     * --auth-basic / --auth-bearer (Phase 16.2). Each credential value is a
     * single whitespace-free CLI token -- Aurora's shell has no quoting. */
    for (;;) {
        if (argi < argc && strcmp(argv[argi], "--post") == 0) {
            method = "POST"; argi++; continue;
        }
        if (argi < argc && strcmp(argv[argi], "--post-multipart") == 0) {
            method = "POST"; is_multipart = 1; argi++; continue;
        }
        if (argi < argc && strcmp(argv[argi], "--method") == 0) {
            argi++;
            if (argi >= argc) { fprintf(2, "%s", usage); return 1; }
            const char *m = method_lookup(argv[argi]);
            if (!m) {
                fprintf(2, "httpsget: --method: unknown method '%s' "
                           "(expected GET, HEAD, OPTIONS, DELETE, POST, PUT, or PATCH)\n", argv[argi]);
                return 1;
            }
            method = m;
            argi++; continue;
        }
        if (argi < argc && strcmp(argv[argi], "--alpn") == 0) {
            g_alpn_enabled = 1; argi++; continue;
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

    if (is_multipart) {
        /* --post-multipart: one path, then one CLI token per field (Phase
         * 16.4) -- Aurora's shell has no quoting, so each "name=value" (or
         * "name=@localfile" for a file part) has to be its own whitespace-
         * free argument; a trailing purely-numeric token is still now_unix,
         * exactly like the GET path below. */
        if (argi >= argc || argv[argi][0] != '/') { fprintf(2, "%s", usage); return 1; }
        paths[0] = argv[argi++]; npaths = 1;

        char *fields[MULTIPART_FIELDS_MAX]; int nfields = 0;
        for (; argi < argc; argi++) {
            char *a = argv[argi];
            int has_eq = 0;
            for (char *p = a; *p; p++) if (*p == '=') { has_eq = 1; break; }
            if (has_eq) {
                if (nfields >= MULTIPART_FIELDS_MAX) {
                    fprintf(2, "httpsget: too many multipart fields (max %d)\n", MULTIPART_FIELDS_MAX); return 1;
                }
                fields[nfields++] = a;
                continue;
            }
            int all_digit = a[0] != 0;
            for (char *p = a; *p; p++) if (*p < '0' || *p > '9') { all_digit = 0; break; }
            if (all_digit) { now = (uint64_t)parse_ul(a); continue; }
            fprintf(2, "httpsget: --post-multipart: unrecognized argument '%s' "
                       "(expected field=value or a numeric now_unix)\n", a);
            return 1;
        }
        if (nfields == 0) { fprintf(2, "httpsget: --post-multipart needs at least one field=value\n"); return 1; }

        gen_boundary(g_boundary, sizeof g_boundary);
        int ctn = 0;
        app(g_multipart_ctype, &ctn, "multipart/form-data; boundary=");
        app(g_multipart_ctype, &ctn, g_boundary);
        g_multipart_ctype[ctn] = 0;

        int blen = build_multipart_body(fields, nfields, g_boundary, g_multipart_body, sizeof g_multipart_body);
        if (blen < 0) {
            fprintf(2, "httpsget: --post-multipart: could not build the request body "
                       "(too large, or a file could not be read -- see above)\n");
            return 1;
        }
        post_body = g_multipart_body;
        post_bodylen = blen;
        content_type = g_multipart_ctype;
    } else if (method_body_bearing(method)) {
        /* --post, or --method POST/PUT/PATCH (Phase 16.5): exactly one path
         * and one body token -- Aurora's shell has no quoting (see
         * build_request()'s doc comment), so the body is whatever single
         * whitespace-free argument follows the path, typically an
         * application/x-www-form-urlencoded string. */
        if (argi >= argc || argv[argi][0] != '/') { fprintf(2, "%s", usage); return 1; }
        paths[0] = argv[argi++]; npaths = 1;
        if (argi >= argc) { fprintf(2, "%s", usage); return 1; }
        post_body = (const uint8_t*)argv[argi];
        post_bodylen = (int)strlen(argv[argi]);
        if (post_bodylen > POST_BODY_MAX) { fprintf(2, "httpsget: body too large (max %d bytes)\n", POST_BODY_MAX); return 1; }
        argi++;
        if (argi < argc) now = (uint64_t)parse_ul(argv[argi]);
    } else {
        /* GET (default), or --method HEAD/OPTIONS/DELETE (Phase 16.5): one
         * or more bodyless paths, same as GET always allowed. */
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

    /* Method tag for the status line below (Phase 16.5 generalizes this from
     * a fixed "(POST)"/"" choice to any non-GET method: "(HEAD)", "(PUT)",
     * "(multipart)", etc.) -- built with app() rather than one more %s
     * placeholder, since the method name itself is now a runtime value, not
     * one of two fixed strings. */
    char method_tag[24]; int mtn = 0;
    if (is_multipart) app(method_tag, &mtn, " (multipart)");
    else if (strcmp(method, "GET") != 0) { app(method_tag, &mtn, " ("); app(method_tag, &mtn, method); app(method_tag, &mtn, ")"); }
    method_tag[mtn] = 0;

    if (npaths == 1)
        printf("[httpsget] %s%s%s%s  (trust store: %u roots)\n", host, paths[0],
               method_tag, g_has_auth ? " (auth)" : "", (unsigned)CA_ROOTS_N);
    else
        printf("[httpsget] %d paths from %s  (trust store: %u roots)\n", npaths, host, (unsigned)CA_ROOTS_N);

    int last_status = 0;
    for (int pi = 0; pi < npaths; pi++) {
        int st = fetch_one(host, paths[pi], now, npaths > 1 ? paths[pi] : 0,
                           method, post_body, post_bodylen, content_type);
        if (st < 0) { close_all_slots(); return 1; }
        last_status = st;
    }
    close_all_slots();

    if (last_status == 200) return 0;
    return last_status ? 0 : 2;
}
