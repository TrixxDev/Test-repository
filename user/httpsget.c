/* httpsget — Aurora's userspace HTTPS client (14.0.3b / 14.0.4 in QEMU).
 *
 * The end-to-end acceptance program: the SAME freestanding TLS/x509/crypto stack,
 * driven over Aurora's OWN network stack (DNS -> TCP -> TLS 1.3 -> HTTP/1.1),
 * fetching a real web page. Deliberately dumb and diagnostic — no keep-alive, no
 * redirects, no cookies, no compression, no HTTP/2.
 *
 *   usage: httpsget <host> [path] [now_unix]      (default path "/", port 443)
 *   e.g.   httpsget github.com /
 *
 * Trust store: a curated set of public CA roots (user/ca_roots.h). A site whose
 * whole chain is RSA-PKCS1-SHA256 or ECDSA-P256-SHA256 verifies; ECDSA P-384/
 * SHA-384 chains (e.g. Let's Encrypt's E-series) are not yet supported (14.x).
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

#define HTTPSGET_NOW 1782864000ULL   /* 2026-07-01; override via argv[3] */

static tls_conn          g_conn;
static tls_record_reader g_reader;
static x509_cert         g_roots[CA_ROOTS_N];
static uint8_t           g_scratch[4096];
static uint8_t           g_plain[17000];
static uint8_t           g_resp[32768];     /* captured response (status+headers+body preview) */
static int               g_fd;

static int xport_read(void *ctx, uint8_t *buf, size_t cap)  { (void)ctx; return read(g_fd, buf, (int)cap); }
static int xport_write(void *ctx, const uint8_t *buf, size_t len) { (void)ctx; return write(g_fd, buf, (int)len); }
static int write_all(const uint8_t *b, int n)
{ int s = 0; while (s < n) { int w = write(g_fd, b + s, n - s); if (w <= 0) return -1; s += w; } return 0; }
static void trace_sink(void *ctx, tls_event ev, uint32_t detail)
{ (void)ctx; (void)detail; printf("[TLS] %s\n", tls_event_name(ev)); }

static int slen(const char *s){ int n=0; while (s[n]) n++; return n; }
static void app(char *d, int *n, const char *s){ for (int i=0; s[i]; i++) d[(*n)++] = s[i]; }
static int ci_eq(const uint8_t *a, const char *b, int n)
{ for (int i=0;i<n;i++){ int x=a[i]|32, y=b[i]|32; if(x!=y) return 0;} return 1; }

static unsigned long parse_ul(const char *s){ unsigned long v=0; while (*s>='0'&&*s<='9') v=v*10+(*s++-'0'); return v; }

static int http_status(const uint8_t *r, int len)
{
    if (len < 12 || !ci_eq(r, "http/1.", 7)) return 0;
    int i = 0; while (i<len && r[i]!=' ') i++; while (i<len && r[i]==' ') i++;
    int c = 0; while (i<len && r[i]>='0' && r[i]<='9') c = c*10 + (r[i++]-'0');
    return c;
}
static int header_end(const uint8_t *r, int len)
{ for (int i=0;i+3<len;i++) if(r[i]=='\r'&&r[i+1]=='\n'&&r[i+2]=='\r'&&r[i+3]=='\n') return i+4; return -1; }
static int hdr_has(const uint8_t *r, int hbe, const char *name, const char *needle)
{
    int nl=slen(name), ndl=slen(needle);
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

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(2, "usage: httpsget <host> [path] [now_unix]\n"); return 1; }
    const char *host = argv[1];
    const char *path = (argc > 2) ? argv[2] : "/";
    uint64_t now = (argc > 3) ? (uint64_t)parse_ul(argv[3]) : HTTPSGET_NOW;
    int port = 443;

    for (unsigned i = 0; i < CA_ROOTS_N; i++)
        if (x509_parse(ca_roots[i].der, ca_roots[i].len, &g_roots[i]) != 0) {
            fprintf(2, "httpsget: trust root %u (%s) failed to parse\n", i, ca_roots[i].name); return 1;
        }
    printf("[httpsget] %s%s  (trust store: %u roots)\n", host, path, (unsigned)CA_ROOTS_N);

    g_fd = inet_socket();
    if (g_fd < 0) { fprintf(2, "httpsget: inet_socket failed\n"); return 1; }
    int rc = inet_connect(g_fd, host, port);
    if (rc == -2) { fprintf(2, "httpsget: DNS resolution failed for %s\n", host); close(g_fd); return 1; }
    if (rc != 0)  { fprintf(2, "httpsget: TCP connect failed (%d)\n", rc); close(g_fd); return 1; }
    printf("[httpsget] TCP connected to %s:%d\n", host, port);

    uint8_t priv[32], crand[32];
    unsigned seed = perf_us() ^ (unsigned)getpid();
    for (int i = 0; i < 32; i++) { seed = seed*1103515245u + 12345u;
        priv[i] = (uint8_t)(i*7+1) ^ (uint8_t)(seed>>16); crand[i] = (uint8_t)(i*3+9) ^ (uint8_t)(seed>>8); }

    tls_conn_init(&g_conn, host, priv, crand);
    tls_client_set_trust(&g_conn.fsm, g_roots, CA_ROOTS_N, now);
    tls_conn_set_trace(&g_conn, trace_sink, 0);
    tls_reader_init(&g_reader);

    tls_transport t = { xport_read, xport_write, 0 };
    int r = tls_driver_handshake(&g_conn, &g_reader, &t, g_scratch, sizeof g_scratch);
    if (r != TLS_DRIVE_OK) {
        fprintf(2, "[httpsget] TLS FAILED (driver=%d, tls_error=%d). For an ECDSA P-384\n"
                   "           chain (e.g. Let's Encrypt E-series) this is the known 14.x gap.\n",
                r, (int)g_conn.fsm.error);
        close(g_fd); return 1;
    }
    int lk = g_conn.fsm.certs.count ? g_conn.fsm.certs.certs[0].pubkey_algo : 0;
    const char *kt = lk == X509_PK_EC ? "EC P-256" : lk == X509_PK_EC384 ? "EC P-384" : "RSA";
    printf("[TLS] Certificate depth=%d  Leaf key=%s  CV scheme=0x%04x\n",
           (int)g_conn.fsm.certs.count, kt, g_conn.fsm.cv_scheme);
    printf("[TLS] CONNECTED\n");

    /* HTTP/1.1 GET over the application epoch */
    char req[512]; int rn = 0;
    app(req,&rn,"GET "); app(req,&rn,path); app(req,&rn," HTTP/1.1\r\nHost: ");
    app(req,&rn,host); app(req,&rn,"\r\nUser-Agent: Aurora-httpsget/0.1\r\nConnection: close\r\n\r\n");
    int sl = tls_conn_send_app(&g_conn, (const uint8_t*)req, (size_t)rn, g_scratch, sizeof g_scratch);
    if (sl < 0 || write_all(g_scratch, sl) != 0) { fprintf(2, "[httpsget] request send failed\n"); close(g_fd); return 1; }
    printf("[httpsget] GET %s HTTP/1.1 sent\n", path);

    int rlen = 0, closed = 0;
    for (;;) {
        const uint8_t *rec; size_t rl; int cc;
        while ((cc = tls_reader_next(&g_reader, &rec, &rl)) == 1) {
            size_t pl = 0;
            int rr = tls_conn_recv_app(&g_conn, rec, rl, g_plain, sizeof g_plain, &pl);
            if (rr == TLS_CONN_ERR_ALERT) { closed = 1; goto show; }
            if (rr < 0) { fprintf(2, "[httpsget] recv_app error %d\n", rr); goto show; }
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
show:
    close(g_fd);
    {
        int status = http_status(g_resp, rlen);
        int hbe = header_end(g_resp, rlen);
        int chunked = (hbe > 0) && hdr_has(g_resp, hbe, "transfer-encoding:", "chunked");
        printf("[httpsget] %d response bytes, status=%d%s\n", rlen, status, closed ? "" : " (truncated preview)");
        /* status line */
        int e = 0; while (e < rlen && g_resp[e] != '\r' && g_resp[e] != '\n') e++;
        g_resp[e < (int)sizeof g_resp ? e : (int)sizeof g_resp - 1] = 0;
        printf("%s\n", (char*)g_resp);
        /* body preview */
        if (hbe > 0) {
            static uint8_t body[8192]; int blen;
            if (chunked) blen = dechunk(g_resp + hbe, rlen - hbe, body, (int)sizeof body);
            else { blen = rlen - hbe; if (blen > (int)sizeof body) blen = (int)sizeof body; memcpy(body, g_resp + hbe, blen); }
            int show = blen < 512 ? blen : 512;
            if (show > 0) { body[show < (int)sizeof body ? show : (int)sizeof body - 1] = 0;
                            printf("[body %d bytes, first %d]:\n%s\n", blen, show, (char*)body); }
        }
        if (status == 200) { printf("\nhttpsget: 200 OK over Aurora TCP->TLS1.3->HTTP\n"); return 0; }
        printf("\nhttpsget: status=%d (not 200)\n", status);
        return status ? 0 : 2;
    }
}
