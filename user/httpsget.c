/* httpsget — Aurora's userspace HTTPS client (14.0.3b / 14.0.4 in QEMU; 15.2
 * adds redirects; 15.4 adds HTTP keep-alive).
 *
 * The end-to-end acceptance program: the SAME freestanding TLS/x509/crypto stack,
 * driven over Aurora's OWN network stack (DNS -> TCP -> TLS 1.3 -> HTTP/1.1),
 * fetching a real web page. Deliberately dumb and diagnostic — no cookies, no
 * compression, no HTTP/2, no pipelining, no connection pool (one connection at
 * a time, requests always fully sequential).
 *
 *   usage: httpsget <host> <path> [path...] [now_unix]   (default path "/", port 443)
 *   e.g.   httpsget github.com /
 *          httpsget example.com / /style.css /logo.png
 *
 * Keep-alive (Phase 15.4): the goal is narrow -- skip a redundant TCP+TLS
 * handshake when the server said we don't need one, nothing more. Each of
 * several paths (given on the command line, or reached via a same-origin
 * redirect) reuses the open connection when the previous response said
 * "Connection: keep-alive" (or defaulted to it under HTTP/1.1) AND had a
 * determinate, bounded length (Content-Length, not chunked, not huge) --
 * otherwise a fresh connection is opened, exactly like every phase before
 * this one. Reuse is optimistic: the next request is just sent on the kept-
 * open socket, and if that write fails (the peer already closed it -- Aurora
 * has no non-blocking way to check liveness up front, see docs/SECURITY.md
 * Step 15.4), the connection is dropped and one fresh reconnect is tried, no
 * attempt to resurrect it. Deliberately NOT here: pipelining, concurrent
 * requests, a connection pool, or a persistent DNS cache -- those are a
 * different, later kind of feature.
 *
 * Redirects (301/302/303/307/308, Phase 15.2) still restart DNS on a host
 * change and the TLS handshake on a scheme change; a same-origin redirect
 * whose predecessor allowed keep-alive reuses the connection instead.
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

#define HTTPSGET_NOW 1782864000ULL   /* 2026-07-01; override via a numeric argument */
#define MAX_REDIRECTS 20             /* hop ceiling; visited[] also catches loops earlier */
#define MAX_PATHS     16
#define FETCH_REUSE_MAX_BODY (64u * 1024u)  /* don't bother draining a response this big just to reuse the connection */

static tls_conn          g_conn;
static tls_record_reader g_reader;
static x509_cert         g_roots[CA_ROOTS_N];
static uint8_t           g_scratch[4096];
static uint8_t           g_plain[17000];
static uint8_t           g_resp[8192];      /* captured response prefix: status + headers + a
                                             * body preview (only ~512 B of body is shown), so a
                                             * few KiB suffices -- not the whole transfer (15.0.4). */
static int               g_fd;
static struct url        g_visited[MAX_REDIRECTS + 1];

static int        g_open;      /* is a TCP[+TLS] session currently open */
static struct url g_session;   /* which host:port:scheme it's bound to, if g_open */

static int xport_read(void *ctx, uint8_t *buf, size_t cap)  { (void)ctx; return read(g_fd, buf, (int)cap); }
static int xport_write(void *ctx, const uint8_t *buf, size_t len) { (void)ctx; return write(g_fd, buf, (int)len); }
static int write_all(const uint8_t *b, int n)
{ int s = 0; while (s < n) { int w = write(g_fd, b + s, n - s); if (w <= 0) return -1; s += w; } return 0; }
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

/* "GET <path> HTTP/1.1\r\nHost: <host>[:<port>]\r\nUser-Agent: ...\r\nConnection:
 * keep-alive\r\n\r\n" -- the port is included only when it isn't the scheme
 * default. We always ask for keep-alive: it costs nothing (the caller closes
 * the connection itself once it decides not to reuse it -- see reusable()),
 * and asking only on "the requests that need it" would require knowing in
 * advance whether a redirect is coming, which we don't. */
static void build_request(char *req, int *rn, const struct url *u)
{
    *rn = 0;
    app(req, rn, "GET "); app(req, rn, u->path); app(req, rn, " HTTP/1.1\r\nHost: ");
    app(req, rn, u->host);
    int defport = u->https ? 443 : 80;
    if (u->port != defport) {
        char t[8]; int tn = 0; unsigned v = (unsigned)u->port;
        do { t[tn++] = (char)('0' + v % 10); v /= 10; } while (v);
        req[(*rn)++] = ':';
        while (tn > 0) req[(*rn)++] = t[--tn];
    }
    app(req, rn, "\r\nUser-Agent: Aurora-httpsget/0.3\r\nConnection: keep-alive\r\n\r\n");
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

static void resp_reset(void)
{
    g_rlen = 0; g_total = 0; g_hdrs_done = 0; g_target = -1;
    memset(&g_hr, 0, sizeof g_hr);
}

static void resp_feed(const uint8_t *data, int n)
{
    if (n <= 0) return;
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
        }
    }
}

/* True once the whole response body has been consumed (only meaningful when
 * reusable() held at header time -- otherwise we stop at the g_resp cap
 * instead, exactly like every phase before 15.4, and just close afterward). */
static int resp_done(void) { return g_target >= 0 && g_total >= g_target; }

#define FETCH_OK    0
#define FETCH_STALE (-2)   /* the write failed: a reused connection was already dead */

/* Open a fresh TCP connection to `u` (a DNS lookup if `u->host` isn't a
 * literal), doing a TLS 1.3 handshake first if `u->https`. On success, g_open
 * = 1 and g_session = *u. On failure, a diagnostic has already been printed
 * and g_open is left however it was (0, since fetch_end() must be called by
 * the caller first when switching targets -- see fetch()). */
static int fetch_begin(const struct url *u, uint64_t now)
{
    g_fd = inet_socket();
    if (g_fd < 0) { fprintf(2, "httpsget: inet_socket failed\n"); return -1; }
    int rc = inet_connect(g_fd, u->host, u->port);
    if (rc == -2) { fprintf(2, "httpsget: DNS resolution failed for %s\n", u->host); close(g_fd); return -1; }
    if (rc != 0)  { fprintf(2, "httpsget: TCP connect failed (%d)\n", rc); close(g_fd); return -1; }
    printf("[httpsget] TCP connected to %s:%d\n", u->host, u->port);

    if (u->https) {
        uint8_t priv[32], crand[32];
        unsigned seed = perf_us() ^ (unsigned)getpid();
        for (int i = 0; i < 32; i++) { seed = seed*1103515245u + 12345u;
            priv[i] = (uint8_t)(i*7+1) ^ (uint8_t)(seed>>16); crand[i] = (uint8_t)(i*3+9) ^ (uint8_t)(seed>>8); }

        tls_conn_init(&g_conn, u->host, priv, crand);
        tls_client_set_trust(&g_conn.fsm, g_roots, CA_ROOTS_N, now);
        tls_conn_set_trace(&g_conn, trace_sink, 0);
        tls_reader_init(&g_reader);

        tls_transport t = { xport_read, xport_write, 0 };
        int r = tls_driver_handshake(&g_conn, &g_reader, &t, g_scratch, sizeof g_scratch);
        if (r != TLS_DRIVE_OK) {
            const char *why = "?";
            if (g_conn.fsm.error == TLS_ERR_CERT) {
                switch (g_conn.fsm.cert_reason) {
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
                        u->host, why, r, g_conn.fsm.cert_reason, (unsigned)CA_ROOTS_N);
            } else {
                const char *e = g_conn.fsm.error == TLS_ERR_AUTH ? "CertificateVerify (key ownership)"
                              : g_conn.fsm.error == TLS_ERR_PROTOCOL ? "protocol/record" : "transport";
                fprintf(2, "[httpsget] TLS FAILED (%s): %s (driver=%d tls_error=%d)\n",
                        u->host, e, r, (int)g_conn.fsm.error);
            }
            close(g_fd); return -1;
        }
        int lk = g_conn.fsm.certs.count ? g_conn.fsm.certs.certs[0].pubkey_algo : 0;
        const char *kt = lk == X509_PK_EC ? "EC P-256" : lk == X509_PK_EC384 ? "EC P-384" : "RSA";
        uint16_t cv = g_conn.fsm.cv_scheme;
        const char *cvn = cv == TLS_SIG_ECDSA_SECP384R1_SHA384 ? "ecdsa_secp384r1_sha384"
                        : cv == TLS_SIG_ECDSA_SECP256R1_SHA256 ? "ecdsa_secp256r1_sha256"
                        : cv == TLS_SIG_RSA_PSS_RSAE_SHA256     ? "rsa_pss_rsae_sha256"
                        : cv == TLS_SIG_RSA_PKCS1_SHA256        ? "rsa_pkcs1_sha256" : "?";
        printf("[TLS] Certificate depth=%d  Leaf key=%s  CV scheme=%s\n",
               (int)g_conn.fsm.certs.count, kt, cvn);
        printf("[TLS] CONNECTED\n");
    }
    g_session = *u;
    g_open = 1;
    return 0;
}

static void fetch_end(void)
{
    if (g_open) close(g_fd);
    g_open = 0;
}

/* Send one GET for u->path over the ALREADY-OPEN session (caller guarantees
 * same_origin(&g_session,u)) and read the response into g_resp / *out. Returns
 * FETCH_OK if a response was obtained (status may be anything, including
 * non-2xx), FETCH_STALE if the write itself failed -- the reused connection
 * was already dead; not a bug, Aurora has no non-blocking way to check that
 * up front, see the header comment -- or -1 on any other transport failure
 * (diagnostic already printed, unrecoverable). */
static int fetch_request(const struct url *u, fetch_result_t *out)
{
    resp_reset();
    char req[768]; int rn;
    build_request(req, &rn, u);

    int closed = 0;
    if (g_session.https) {
        int sl = tls_conn_send_app(&g_conn, (const uint8_t*)req, (size_t)rn, g_scratch, sizeof g_scratch);
        if (sl < 0) return FETCH_STALE;
        if (write_all(g_scratch, sl) != 0) return FETCH_STALE;
        printf("[httpsget] GET %s HTTP/1.1 sent\n", u->path);

        for (;;) {
            const uint8_t *rec; size_t rl; int cc;
            while ((cc = tls_reader_next(&g_reader, &rec, &rl)) == 1) {
                size_t pl = 0;
                int rr = tls_conn_recv_app(&g_conn, rec, rl, g_plain, sizeof g_plain, &pl);
                if (rr == TLS_CONN_ERR_ALERT) { closed = 1; goto https_done; }
                if (rr < 0) { fprintf(2, "[httpsget] recv_app error %d\n", rr); goto https_done; }
                resp_feed(g_plain, (int)pl);
                if (resp_done()) goto https_done;
            }
            if (cc < 0) { fprintf(2, "[httpsget] malformed record\n"); break; }
            if (g_target < 0 && g_rlen >= (int)sizeof g_resp) break;   /* not reusable: preview cap reached */
            int n = read(g_fd, g_scratch, sizeof g_scratch);
            if (n <= 0) { closed = 1; break; }
            tls_reader_feed(&g_reader, g_scratch, (size_t)n);
        }
        https_done: ;
    } else {
        if (write_all((const uint8_t*)req, rn) != 0) return FETCH_STALE;
        printf("[httpsget] GET %s HTTP/1.1 sent (plain HTTP)\n", u->path);

        for (;;) {
            if (resp_done()) break;
            if (g_target < 0 && g_rlen >= (int)sizeof g_resp) break;
            int n = read(g_fd, g_scratch, sizeof g_scratch);
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

    out->hr    = g_hr;
    out->rlen  = g_rlen;
    out->closed = closed;
    return FETCH_OK;
}

/* Ensure a session is open and matches `u` (reusing, reconnecting, or opening
 * fresh as needed), then send one GET and read the response. Returns 0 on a
 * response obtained (fr is filled), -1 on an unrecoverable transport failure
 * (diagnostic already printed, caller should give up). */
static int fetch(const struct url *u, uint64_t now, fetch_result_t *out)
{
    if (g_open && same_origin(&g_session, u)) {
        printf("[httpsget] reusing open connection to %s:%d (keep-alive)\n", u->host, u->port);
        int rc = fetch_request(u, out);
        if (rc == FETCH_OK) return 0;
        if (rc != FETCH_STALE) return -1;
        printf("[httpsget] reused connection to %s:%d was already closed -- reconnecting\n", u->host, u->port);
        fetch_end();
    } else {
        fetch_end();     /* close whatever's open; it isn't this target */
    }
    if (fetch_begin(u, now) != 0) return -1;
    int rc = fetch_request(u, out);
    if (rc == FETCH_OK) return 0;
    if (rc == FETCH_STALE)
        fprintf(2, "[httpsget] connection to %s:%d closed before the request could be sent\n", u->host, u->port);
    return -1;
}

/* Fetch one top-level path (following redirects, Phase 15.2) and print its
 * result. Returns the final HTTP status (0 if no valid response was ever
 * obtained), or -1 on an unrecoverable transport failure. `label` is printed
 * as a header when there's more than one path in this run. */
static int fetch_one(const char *host, const char *path, uint64_t now, const char *label)
{
    struct url u; memset(&u, 0, sizeof u);
    u.https = 1; u.port = 443;
    { int i = 0; for (; host[i] && i < (int)sizeof(u.host) - 1; i++) u.host[i] = host[i]; u.host[i] = 0; }
    { int i = 0; for (; path[i] && i < (int)sizeof(u.path) - 1; i++) u.path[i] = path[i]; u.path[i] = 0; }
    if (!u.path[0]) { u.path[0] = '/'; u.path[1] = 0; }

    if (label) printf("[httpsget] ==== %s ====\n", label);

    int nvisited = 0, hop = 0;
    fetch_result_t fr;

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
            printf("[httpsget] -- hop %d/%d: %s://%s:%d%s\n", hop, MAX_REDIRECTS,
                   u.https ? "https" : "http", u.host, u.port, u.path);

        if (fetch(&u, now, &fr) != 0) return -1;    /* diagnostic already printed */
        if (!reusable(&fr.hr)) fetch_end();

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
            /* body preview */
            if (hbe > 0 && hbe <= fr.rlen) {
                static uint8_t body[8192]; int blen;
                if (fr.hr.chunked) blen = dechunk(g_resp + hbe, fr.rlen - hbe, body, (int)sizeof body);
                else { blen = fr.rlen - hbe; if (blen > (int)sizeof body) blen = (int)sizeof body; memcpy(body, g_resp + hbe, blen); }
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
        u = next;
        hop++;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(2, "usage: httpsget <host> <path> [path...] [now_unix]\n"); return 1; }
    const char *host = argv[1];
    const char *paths[MAX_PATHS]; int npaths = 0;
    uint64_t now = HTTPSGET_NOW;
    for (int i = 2; i < argc; i++) {
        if (argv[i][0] == '/') { if (npaths < MAX_PATHS) paths[npaths++] = argv[i]; }
        else now = (uint64_t)parse_ul(argv[i]);
    }
    if (npaths == 0) { paths[0] = "/"; npaths = 1; }

    for (unsigned i = 0; i < CA_ROOTS_N; i++)
        if (x509_parse(ca_roots[i].der, ca_roots[i].len, &g_roots[i]) != 0) {
            fprintf(2, "httpsget: trust root %u (%s) failed to parse\n", i, ca_roots[i].name); return 1;
        }

    if (npaths == 1)
        printf("[httpsget] %s%s  (trust store: %u roots)\n", host, paths[0], (unsigned)CA_ROOTS_N);
    else
        printf("[httpsget] %d paths from %s  (trust store: %u roots)\n", npaths, host, (unsigned)CA_ROOTS_N);

    int last_status = 0;
    for (int pi = 0; pi < npaths; pi++) {
        int st = fetch_one(host, paths[pi], now, npaths > 1 ? paths[pi] : 0);
        if (st < 0) { fetch_end(); return 1; }
        last_status = st;
    }
    fetch_end();

    if (last_status == 200) return 0;
    return last_status ? 0 : 2;
}
