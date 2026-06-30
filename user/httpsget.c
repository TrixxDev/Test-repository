/* httpsget — Aurora's userspace HTTPS client (14.0.3b / 14.0.4 in QEMU; 15.2
 * adds redirects).
 *
 * The end-to-end acceptance program: the SAME freestanding TLS/x509/crypto stack,
 * driven over Aurora's OWN network stack (DNS -> TCP -> TLS 1.3 -> HTTP/1.1),
 * fetching a real web page. Deliberately dumb and diagnostic — no keep-alive, no
 * cookies, no compression, no HTTP/2.
 *
 *   usage: httpsget <host> [path] [now_unix]      (default path "/", port 443)
 *   e.g.   httpsget github.com /
 *
 * Redirects (301/302/303/307/308, Phase 15.2) are followed as a brand-new
 * transaction each time: a fresh DNS lookup, a fresh TCP connect, and (since the
 * scheme may change) either a fresh TLS handshake or a plain HTTP request, then a
 * fresh GET. No TLS session is ever reused across hops — full restart is simpler
 * and safer to reason about than carrying state across a redirect; keep-alive and
 * session resumption are later phases that don't change this shape. A hard
 * MAX_REDIRECTS ceiling plus a visited-URL list (loop detection) bound the work.
 *
 * Trust store: a curated set of public CA roots (user/ca_roots.h). A site whose
 * whole chain is RSA-PKCS1-SHA256, ECDSA-P256-SHA256 or ECDSA-P384-SHA384
 * verifies against an RSA or ECDSA root (15.1).
 *
 * Aurora has no wall clock, so the validity instant is a build-time constant
 * (overridable as the 3rd argument) — keep it inside the target cert's window. */
#include "libc.h"
#include "driver.h"
#include "conn.h"
#include "client.h"
#include "x509.h"
#include "cert.h"
#include "ca_roots.h"
#include "url.h"
#include "http.h"

#define HTTPSGET_NOW 1782864000ULL   /* 2026-07-01; override via argv[3] */
#define MAX_REDIRECTS 20             /* hop ceiling; visited[] also catches loops earlier */

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

static int xport_read(void *ctx, uint8_t *buf, size_t cap)  { (void)ctx; return read(g_fd, buf, (int)cap); }
static int xport_write(void *ctx, const uint8_t *buf, size_t len) { (void)ctx; return write(g_fd, buf, (int)len); }
static int write_all(const uint8_t *b, int n)
{ int s = 0; while (s < n) { int w = write(g_fd, b + s, n - s); if (w <= 0) return -1; s += w; } return 0; }
static void trace_sink(void *ctx, tls_event ev, uint32_t detail)
{ (void)ctx; (void)detail; printf("[TLS] %s\n", tls_event_name(ev)); }

static void app(char *d, int *n, const char *s){ for (int i = 0; s[i]; i++) d[(*n)++] = s[i]; }
static int ci_eq(const uint8_t *a, const char *b, int n)
{ for (int i=0;i<n;i++){ int x=a[i]|32, y=b[i]|32; if(x!=y) return 0;} return 1; }

static unsigned long parse_ul(const char *s){ unsigned long v=0; while (*s>='0'&&*s<='9') v=v*10+(*s++-'0'); return v; }

static int hdr_has(const uint8_t *r, int hbe, const char *name, const char *needle)
{
    int nl=0; while(name[nl]) nl++; int ndl=0; while(needle[ndl]) ndl++;
    for (int i=0;i+nl<hbe;i++) if ((i==0||r[i-1]=='\n')&&ci_eq(r+i,name,nl))
        for (int j=i+nl;j+ndl<=hbe&&r[j]!='\n';j++) if (ci_eq(r+j,needle,ndl)) return 1;
    return 0;
}
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

/* "GET <path> HTTP/1.1\r\nHost: <host>[:<port>]\r\nUser-Agent: ...\r\nConnection:
 * close\r\n\r\n" -- the port is included only when it isn't the scheme default,
 * matching normal browser behavior. */
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
    app(req, rn, "\r\nUser-Agent: Aurora-httpsget/0.2\r\nConnection: close\r\n\r\n");
}

typedef struct {
    struct http_response hr;
    int rlen;
    int closed;          /* did the peer close (full capture), or did we hit the g_resp cap? */
} fetch_result_t;

/* One full DNS -> TCP -> [TLS] -> HTTP/1.1 GET transaction against `u`, captured
 * into g_resp / *out. Returns 0 if an HTTP response was obtained (status may be
 * anything, including non-2xx) -- the caller decides what to do with it. Returns
 * -1 on a network/TLS-layer failure; a diagnostic has already been printed and
 * the caller must stop (there is no response to act on). */
static int do_fetch(const struct url *u, uint64_t now, fetch_result_t *out)
{
    out->rlen = 0; out->closed = 0;

    g_fd = inet_socket();
    if (g_fd < 0) { fprintf(2, "httpsget: inet_socket failed\n"); return -1; }
    int rc = inet_connect(g_fd, u->host, u->port);
    if (rc == -2) { fprintf(2, "httpsget: DNS resolution failed for %s\n", u->host); close(g_fd); return -1; }
    if (rc != 0)  { fprintf(2, "httpsget: TCP connect failed (%d)\n", rc); close(g_fd); return -1; }
    printf("[httpsget] TCP connected to %s:%d\n", u->host, u->port);

    int rlen = 0, closed = 0;
    char req[768]; int rn;

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

        build_request(req, &rn, u);
        int sl = tls_conn_send_app(&g_conn, (const uint8_t*)req, (size_t)rn, g_scratch, sizeof g_scratch);
        if (sl < 0 || write_all(g_scratch, sl) != 0) { fprintf(2, "[httpsget] request send failed\n"); close(g_fd); return -1; }
        printf("[httpsget] GET %s HTTP/1.1 sent\n", u->path);

        for (;;) {
            const uint8_t *rec; size_t rl; int cc;
            while ((cc = tls_reader_next(&g_reader, &rec, &rl)) == 1) {
                size_t pl = 0;
                int rr = tls_conn_recv_app(&g_conn, rec, rl, g_plain, sizeof g_plain, &pl);
                if (rr == TLS_CONN_ERR_ALERT) { closed = 1; goto https_done; }
                if (rr < 0) { fprintf(2, "[httpsget] recv_app error %d\n", rr); goto https_done; }
                if (pl > 0 && rlen < (int)sizeof g_resp) {
                    int c = (rlen + (int)pl <= (int)sizeof g_resp) ? (int)pl : (int)sizeof g_resp - rlen;
                    memcpy(g_resp + rlen, g_plain, c); rlen += c;
                }
            }
            if (cc < 0) { fprintf(2, "[httpsget] malformed record\n"); break; }
            if (rlen >= (int)sizeof g_resp) break;     /* captured enough for a diagnostic preview */
            int n = read(g_fd, g_scratch, sizeof g_scratch);
            if (n <= 0) { closed = 1; break; }
            tls_reader_feed(&g_reader, g_scratch, (size_t)n);
        }
        https_done: ;
    } else {
        build_request(req, &rn, u);
        if (write_all((const uint8_t*)req, rn) != 0) { fprintf(2, "[httpsget] request send failed\n"); close(g_fd); return -1; }
        printf("[httpsget] GET %s HTTP/1.1 sent (plain HTTP)\n", u->path);
        for (;;) {
            if (rlen >= (int)sizeof g_resp) break;
            int n = read(g_fd, g_resp + rlen, sizeof(g_resp) - rlen);
            if (n <= 0) { closed = 1; break; }
            rlen += n;
        }
    }
    close(g_fd);

    out->rlen = rlen;
    out->closed = closed;
    http_parse((const char*)g_resp, rlen, &out->hr);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(2, "usage: httpsget <host> [path] [now_unix]\n"); return 1; }
    const char *host = argv[1];
    const char *path = (argc > 2) ? argv[2] : "/";
    uint64_t now = (argc > 3) ? (uint64_t)parse_ul(argv[3]) : HTTPSGET_NOW;

    for (unsigned i = 0; i < CA_ROOTS_N; i++)
        if (x509_parse(ca_roots[i].der, ca_roots[i].len, &g_roots[i]) != 0) {
            fprintf(2, "httpsget: trust root %u (%s) failed to parse\n", i, ca_roots[i].name); return 1;
        }

    struct url u; memset(&u, 0, sizeof u);
    u.https = 1; u.port = 443;
    { int i = 0; for (; host[i] && i < (int)sizeof(u.host) - 1; i++) u.host[i] = host[i]; u.host[i] = 0; }
    { int i = 0; for (; path[i] && i < (int)sizeof(u.path) - 1; i++) u.path[i] = path[i]; u.path[i] = 0; }
    if (!u.path[0]) { u.path[0] = '/'; u.path[1] = 0; }

    printf("[httpsget] %s%s  (trust store: %u roots)\n", u.host, u.path, (unsigned)CA_ROOTS_N);

    int nvisited = 0, hop = 0;
    fetch_result_t fr;

    for (;;) {
        for (int i = 0; i < nvisited; i++)
            if (url_eq(&g_visited[i], &u)) {
                fprintf(2, "[httpsget] redirect loop detected at %s://%s%s -- aborting\n",
                        u.https ? "https" : "http", u.host, u.path);
                return 1;
            }
        if (nvisited >= MAX_REDIRECTS + 1) {
            fprintf(2, "[httpsget] too many redirects (limit %d) -- aborting\n", MAX_REDIRECTS);
            return 1;
        }
        g_visited[nvisited++] = u;

        if (hop > 0)
            printf("[httpsget] -- hop %d/%d: %s://%s:%d%s\n", hop, MAX_REDIRECTS,
                   u.https ? "https" : "http", u.host, u.port, u.path);

        if (do_fetch(&u, now, &fr) != 0) return 1;     /* diagnostic already printed */

        int st = fr.hr.status;
        int is_redirect = st == 301 || st == 302 || st == 303 || st == 307 || st == 308;
        if (!is_redirect) break;

        if (!fr.hr.location[0]) {
            fprintf(2, "[httpsget] redirect status %d with no usable Location header -- stopping\n", st);
            break;
        }
        struct url next;
        if (url_resolve(&u, fr.hr.location, (int)strlen(fr.hr.location), &next) != 0) {
            fprintf(2, "[httpsget] could not resolve redirect Location '%s' -- stopping\n", fr.hr.location);
            break;
        }
        printf("[httpsget] %d redirect -> %s\n", st, fr.hr.location);
        u = next;
        hop++;
    }

    {
        int status = fr.hr.status;
        int hbe = fr.hr.header_len;
        int chunked = hdr_has(g_resp, hbe, "transfer-encoding:", "chunked");
        printf("[httpsget] %d response bytes, status=%d%s\n", fr.rlen, status, fr.closed ? "" : " (truncated preview)");
        /* status line */
        int e = 0; while (e < fr.rlen && g_resp[e] != '\r' && g_resp[e] != '\n') e++;
        g_resp[e < (int)sizeof g_resp ? e : (int)sizeof g_resp - 1] = 0;
        printf("%s\n", (char*)g_resp);
        /* body preview */
        if (hbe > 0 && hbe <= fr.rlen) {
            static uint8_t body[8192]; int blen;
            if (chunked) blen = dechunk(g_resp + hbe, fr.rlen - hbe, body, (int)sizeof body);
            else { blen = fr.rlen - hbe; if (blen > (int)sizeof body) blen = (int)sizeof body; memcpy(body, g_resp + hbe, blen); }
            int show = blen < 512 ? blen : 512;
            if (show > 0) { body[show < (int)sizeof body ? show : (int)sizeof body - 1] = 0;
                            printf("[body %d bytes, first %d]:\n%s\n", blen, show, (char*)body); }
        }
        const char *via = hop == 0 ? "" : " after redirects";
        if (status == 200) { printf("\nhttpsget: 200 OK over Aurora TCP->TLS1.3->HTTP%s\n", via); return 0; }
        printf("\nhttpsget: status=%d (not 200)%s\n", status, via);
        return status ? 0 : 2;
    }
}
