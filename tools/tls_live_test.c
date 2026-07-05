/* 14.0.3a + 14.0.4 — Live Internet TLS + HTTP/1.1 over Aurora's real engine, host.
 *
 * Aurora's TLS/x509/crypto code is portable freestanding C — the SAME objects
 * that link into the QEMU userspace client. This harness runs that engine against
 * a real TLS 1.3 server on the public internet, using host sockets only as the
 * byte transport (through the environment's HTTPS CONNECT proxy). It proves the
 * full browser network stack on genuine bytes BEFORE the QEMU bring-up:
 *
 *   TCP -> proxy CONNECT -> Aurora tls_driver -> CONNECTED        (14.0.3a)
 *        -> HTTP/1.1 GET -> reassemble response -> 200 + body     (14.0.4)
 *
 * The GET is sealed over the application epoch; the response is reassembled across
 * many application_data records (de-chunking or Content-Length), exercising the
 * app traffic keys, nonce derivation, and record coalescing/fragmentation on real
 * bytes. Trust anchor: a PEM named by AURORA_TRUST_PEM (so this sandbox's
 * TLS-inspecting proxy CA can anchor a REAL verification), else the embedded ISRG
 * Root X1. Build/run: `make tls-live-test`. Needs outbound network.
 *
 *   usage: tls-live-test [host] [port]   (default github.com 443 via the Makefile)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "driver.h"
#include "conn.h"
#include "client.h"
#include "x509.h"
#include "cert.h"
#include "uprof.h"

/* Phase 18.5.3: see tools/tls_test.c's identical stub -- tls/record.c's
 * AEAD timing calls this; a fake incrementing counter is fine here since
 * this test checks a real live handshake/response, not timing. */
uint64_t cprof_now_us(void) { static uint64_t t; return t++; }

/* ISRG Root X1 (Let's Encrypt root), DER. */
#define ISRG_X1 "3082056b30820353a0030201020211008210cfb0d240e3594463e0bb63828b00300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3135303630343131303433385a170d3335303630343131303433385a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b05000382020100551f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d321977ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea912b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b573a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b52ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355ca328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdca2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073fb9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade1827"

static tls_conn          g_conn;
static tls_record_reader g_reader;
static x509_cert         g_root;
static uint8_t           g_root_der[2048];
static uint8_t           g_scratch[17000];   /* >= one full TLS record */
static uint8_t           g_plain[17000];
static int               g_fd = -1;
static long              g_hs_bytes = 0;   /* total transport bytes read during handshake */

static int unhex(const char *s, uint8_t *out)
{
    int n = 0;
    for (; s[0] && s[1]; s += 2) {
        int hi = s[0] <= '9' ? s[0]-'0' : (s[0]|32)-'a'+10;
        int lo = s[1] <= '9' ? s[1]-'0' : (s[1]|32)-'a'+10;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static int b64val(int c)
{
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;
    if (c=='+') return 62; if (c=='/') return 63; return -1;
}
/* Load the first CERTIFICATE block from a PEM file into out (DER). Returns DER
 * length, or -1. Used so the trust anchor can come from the environment's CA
 * (e.g. a TLS-inspecting proxy's CA) rather than being hardcoded. */
static int load_pem_cert(const char *path, uint8_t *out, int cap)
{
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    char line[512]; int in = 0, acc = 0, nbits = 0, dl = 0;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "BEGIN CERTIFICATE")) { in = 1; continue; }
        if (strstr(line, "END CERTIFICATE")) break;
        if (!in) continue;
        for (char *p = line; *p; p++) {
            if (isspace((unsigned char)*p)) continue;
            if (*p == '=') continue;
            int v = b64val((unsigned char)*p); if (v < 0) continue;
            acc = (acc << 6) | v; nbits += 6;
            if (nbits >= 8) { nbits -= 8; if (dl < cap) out[dl++] = (uint8_t)(acc >> nbits); }
        }
    }
    fclose(f);
    return in ? dl : -1;
}

static int xport_read(void *ctx, uint8_t *buf, size_t cap)
{
    (void)ctx;
    int n = (int)read(g_fd, buf, cap);
    if (n > 0) { g_hs_bytes += n; printf("[net] recv %d bytes\n", n); }
    return n;
}
static int xport_write(void *ctx, const uint8_t *buf, size_t len)
{ (void)ctx; return (int)write(g_fd, buf, len); }

static void trace_sink(void *ctx, tls_event ev, uint32_t detail)
{ (void)ctx; (void)detail; printf("[TLS] %s\n", tls_event_name(ev)); }

/* Open a TCP tunnel to host:port through the HTTPS_PROXY CONNECT proxy. */
static int proxy_connect(const char *host, int port)
{
    const char *px = getenv("HTTPS_PROXY"); if (!px) px = getenv("https_proxy");
    if (!px) { fprintf(stderr, "no HTTPS_PROXY in env\n"); return -1; }
    const char *p = px; if (!strncmp(p, "http://", 7)) p += 7;
    char phost[128]; int pport = 0; int i = 0;
    for (; p[i] && p[i] != ':' && i < (int)sizeof phost - 1; i++) phost[i] = p[i];
    phost[i] = 0;
    if (p[i] == ':') for (p += i + 1; *p >= '0' && *p <= '9'; p++) pport = pport*10 + (*p-'0');
    if (!pport) pport = 8080;

    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)pport);
    if (inet_pton(AF_INET, phost, &sa.sin_addr) != 1) {
        struct hostent *he = gethostbyname(phost);
        if (!he) { fprintf(stderr, "proxy host resolve failed: %s\n", phost); return -1; }
        memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) < 0) { perror("connect proxy"); close(fd); return -1; }

    char req[256];
    int rl = snprintf(req, sizeof req, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port);
    if (write(fd, req, rl) != rl) { perror("write CONNECT"); close(fd); return -1; }

    /* read the CONNECT response headers byte-by-byte up to the blank line (so we
     * never swallow any TLS bytes that might follow) */
    char resp[512]; int rn = 0; int ok = 0;
    while (rn < (int)sizeof resp - 1) {
        char c; int k = (int)read(fd, &c, 1);
        if (k <= 0) break;
        resp[rn++] = c;
        if (rn >= 4 && resp[rn-4]=='\r' && resp[rn-3]=='\n' && resp[rn-2]=='\r' && resp[rn-1]=='\n') { ok = 1; break; }
    }
    resp[rn] = 0;
    if (!ok || !strstr(resp, " 200 ")) {
        fprintf(stderr, "proxy CONNECT failed:\n%s\n", resp); close(fd); return -1;
    }
    printf("[proxy] CONNECT %s:%d established\n", host, port);
    return fd;
}

/* --- minimal HTTP/1.1 response parsing (host-side, for the 14.0.4 proof) --- */
static int ci_eq(const uint8_t *a, const char *b, int n)
{ for (int i=0;i<n;i++){ int x=a[i]|32, y=b[i]|32; if(x!=y) return 0;} return 1; }

static int http_status(const uint8_t *r, int len)        /* status code, or 0 */
{
    if (len < 12 || !ci_eq(r, "http/1.", 7)) return 0;
    int i = 0; while (i<len && r[i]!=' ') i++; while (i<len && r[i]==' ') i++;
    int code = 0; while (i<len && r[i]>='0' && r[i]<='9') code = code*10 + (r[i++]-'0');
    return code;
}
static int header_end(const uint8_t *r, int len)         /* offset past CRLFCRLF, or -1 */
{
    for (int i=0; i+3<len; i++) if (r[i]=='\r'&&r[i+1]=='\n'&&r[i+2]=='\r'&&r[i+3]=='\n') return i+4;
    return -1;
}
/* does a header named `name` contain `needle` (both case-insensitive)? */
static int hdr_has(const uint8_t *r, int hbe, const char *name, const char *needle)
{
    int nl = (int)strlen(name), ndl = (int)strlen(needle);
    for (int i=0; i+nl<hbe; i++) {
        if ((i==0 || r[i-1]=='\n') && ci_eq(r+i, name, nl)) {
            for (int j=i+nl; j+ndl<=hbe && r[j]!='\n'; j++) if (ci_eq(r+j, needle, ndl)) return 1;
        }
    }
    return 0;
}
static int hdr_content_length(const uint8_t *r, int hbe)  /* value, or -1 */
{
    const char *k = "content-length:"; int kl = (int)strlen(k);
    for (int i=0; i+kl<hbe; i++) {
        if ((i==0 || r[i-1]=='\n') && ci_eq(r+i, k, kl)) {
            int j=i+kl; while (j<hbe && r[j]==' ') j++;
            int v=0, any=0; while (j<hbe && r[j]>='0'&&r[j]<='9'){ v=v*10+(r[j++]-'0'); any=1; }
            return any ? v : -1;
        }
    }
    return -1;
}
/* Decode chunked transfer-encoding. Returns decoded length, or -1. */
static int dechunk(const uint8_t *in, int len, uint8_t *out, int outcap)
{
    int i=0, o=0;
    for (;;) {
        int sz=0, any=0;
        while (i<len) { int c=in[i],d; if(c>='0'&&c<='9')d=c-'0';
                        else if((c|32)>='a'&&(c|32)<='f')d=(c|32)-'a'+10; else break; sz=sz*16+d; any=1; i++; }
        if (!any) return o>0?o:-1;
        while (i<len && in[i]!='\n') i++; if (i<len) i++;          /* skip rest of size line */
        if (sz==0) break;                                          /* final chunk */
        if (i+sz>len || o+sz>outcap) return o;                     /* truncated: return what we have */
        memcpy(out+o, in+i, sz); o+=sz; i+=sz;
        if (i<len && in[i]=='\r') i++; if (i<len && in[i]=='\n') i++;
    }
    return o;
}

static const char *keytype(int a){ return a==X509_PK_RSA?"RSA":a==X509_PK_EC?"EC":"unknown"; }
static const char *scheme_name(uint16_t s){
    switch (s){ case TLS_SIG_RSA_PSS_RSAE_SHA256: return "rsa_pss_rsae_sha256";
                case TLS_SIG_ECDSA_SECP256R1_SHA256: return "ecdsa_secp256r1_sha256";
                case TLS_SIG_RSA_PKCS1_SHA256: return "rsa_pkcs1_sha256";
                default: return "?"; }
}

int main(int argc, char **argv)
{
    const char *host = (argc > 1) ? argv[1] : "www.eff.org";
    int port = (argc > 2) ? atoi(argv[2]) : 443;

    /* Trust anchor: a PEM file named by AURORA_TRUST_PEM if set (so this sandbox's
     * TLS-inspecting proxy CA, /root/.ccr/agent-proxy-ca.crt, can be the anchor and
     * the verification stays REAL — pre-trusted out of band), else embedded ISRG
     * Root X1 for genuine public RSA chains. */
    const char *trust_pem = getenv("AURORA_TRUST_PEM");
    int dl = -1;
    if (trust_pem && trust_pem[0]) {
        dl = load_pem_cert(trust_pem, g_root_der, (int)sizeof g_root_der);
        if (dl > 0) printf("[live] trust anchor: %s\n", trust_pem);
    }
    if (dl <= 0) { dl = unhex(ISRG_X1, g_root_der); printf("[live] trust anchor: embedded ISRG Root X1\n"); }
    if (x509_parse(g_root_der, dl, &g_root) != 0) {
        fprintf(stderr, "trust anchor failed to parse\n"); return 1;
    }

    g_fd = proxy_connect(host, port);
    if (g_fd < 0) return 1;
    struct timeval tv = { 15, 0 };           /* don't block forever waiting for records */
    setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t priv[32], crand[32];
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (int i = 0; i < 32; i++) { priv[i] = (uint8_t)rand(); crand[i] = (uint8_t)rand(); }

    uint64_t now = (uint64_t)time(NULL);
    printf("[live] target %s:%d  now=%llu (host clock)\n", host, port, (unsigned long long)now);

    tls_conn_init(&g_conn, host, priv, crand);
    tls_client_set_trust(&g_conn.fsm, &g_root, 1, now);
    tls_conn_set_trace(&g_conn, trace_sink, 0);
    tls_reader_init(&g_reader);

    tls_transport t = { xport_read, xport_write, 0 };
    int r = tls_driver_handshake(&g_conn, &g_reader, &t, g_scratch, sizeof g_scratch);
    if (r != TLS_DRIVE_OK) {
        fprintf(stderr, "[live] handshake FAILED: driver=%d tls_error=%d\n", r, (int)g_conn.fsm.error);
        close(g_fd); return 1;
    }

    /* post-handshake diagnostics the user asked for */
    printf("[TLS] Certificate depth=%zu\n", g_conn.fsm.certs.count);
    printf("[TLS] Leaf key=%s\n", g_conn.fsm.certs.count ? keytype(g_conn.fsm.certs.certs[0].pubkey_algo) : "?");
    printf("[TLS] CV scheme=%s (0x%04x)\n", scheme_name(g_conn.fsm.cv_scheme), g_conn.fsm.cv_scheme);
    printf("[TLS] handshake bytes read=%ld\n", g_hs_bytes);
    printf("[TLS] CONNECTED\n");

    /* 14.0.4 — a real HTTP/1.1 GET over the live TLS channel: send the request,
     * read every application_data record until the server closes, reassemble the
     * response, then parse status + body (de-chunking or Content-Length). */
    {
        char req[256];
        int rql = snprintf(req, sizeof req,
                           "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Aurora/0.1\r\nConnection: close\r\n\r\n", host);
        int sl = tls_conn_send_app(&g_conn, (const uint8_t*)req, (size_t)rql, g_scratch, sizeof g_scratch);
        if (sl <= 0 || write(g_fd, g_scratch, sl) != sl) {
            fprintf(stderr, "[http] request send failed\n"); close(g_fd); return 1;
        }
        printf("[http] GET / HTTP/1.1 sent (%d bytes, sealed over the app epoch)\n", rql);
    }

    static uint8_t resp[262144]; int rlen = 0, nrec = 0, closed = 0;
    for (;;) {
        const uint8_t *rec; size_t rl; int rc;
        while ((rc = tls_reader_next(&g_reader, &rec, &rl)) == 1) {
            size_t pl = 0;
            int cc = tls_conn_recv_app(&g_conn, rec, rl, g_plain, sizeof g_plain, &pl);
            if (cc == TLS_CONN_ERR_ALERT) { printf("[TLS] close_notify\n"); closed = 1; goto parse; }
            if (cc < 0) { fprintf(stderr, "[http] recv_app error %d\n", cc); goto parse; }
            nrec++;
            if (pl > 0) { int c = (rlen + (int)pl <= (int)sizeof resp) ? (int)pl : (int)sizeof resp - rlen;
                          memcpy(resp + rlen, g_plain, c); rlen += c; }
        }
        if (rc < 0) { fprintf(stderr, "[http] malformed record\n"); break; }
        int n = (int)read(g_fd, g_scratch, sizeof g_scratch);
        if (n <= 0) { closed = 1; break; }       /* clean TCP EOF / Connection: close */
        tls_reader_feed(&g_reader, g_scratch, (size_t)n);
    }
parse:
    close(g_fd);
    printf("[http] %d app records, %d response bytes, closed=%d\n", nrec, rlen, closed);

    int status = http_status(resp, rlen);
    int hbe = header_end(resp, rlen);            /* offset just past CRLFCRLF */
    int chunked = (hbe > 0) && hdr_has(resp, hbe, "transfer-encoding:", "chunked");
    int clen = (hbe > 0) ? hdr_content_length(resp, hbe) : -1;

    static uint8_t body[262144]; int blen = 0;
    if (hbe > 0) {
        if (chunked)       blen = dechunk(resp + hbe, rlen - hbe, body, (int)sizeof body);
        else if (clen >= 0) blen = (clen <= rlen - hbe) ? clen : rlen - hbe, memcpy(body, resp + hbe, blen);
        else               blen = rlen - hbe, memcpy(body, resp + hbe, blen);   /* until close */
    }
    printf("[http] status=%d  headers=%dB  body=%dB%s%s\n", status, hbe, blen,
           chunked ? " (chunked)" : (clen >= 0 ? " (content-length)" : " (until-close)"),
           closed ? "" : " [no clean close]");
    if (blen > 0) { int show = blen < 120 ? blen : 120;
                    printf("[http] body[0..%d]: %.*s%s\n", show, show, (char*)body, blen > show ? " ..." : ""); }

    if (status == 200 && blen > 0) {
        printf("\nHTTPS GET TEST: PASS (real HTTP/1.1 200 over Aurora TCP->TLS1.3->HTTP, %d-byte body)\n", blen);
        return 0;
    }
    printf("\nHTTPS GET TEST: status=%d body=%d -- not a clean 200 (see above)\n", status, blen);
    return 2;
}
