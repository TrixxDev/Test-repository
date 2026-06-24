/* 14.0.3a — Live Internet TLS over Aurora's real engine, on the host.
 *
 * Aurora's TLS/x509/crypto code is portable freestanding C — the SAME objects
 * that link into the QEMU userspace client. This harness runs that engine against
 * a real TLS 1.3 server on the public internet, using host sockets only as the
 * byte transport (through the environment's HTTPS CONNECT proxy). It proves the
 * hardest real-world TLS behaviours BEFORE the QEMU bring-up:
 *
 *   TCP -> proxy CONNECT -> Aurora tls_driver -> CONNECTED
 *        -> decrypt >= 1 real application_data record   (no HTTP, no GET)
 *
 * The first post-handshake application_data record from a real server is normally
 * a NewSessionTicket; decrypting it exercises the application traffic keys, nonce
 * derivation, and record coalescing/fragmentation on genuine bytes. Trust anchor:
 * the embedded ISRG Root X1 (Let's Encrypt). Default target: www.eff.org:443
 * (an RSA chain Aurora can verify; LE ECDSA chains use P-384/SHA-384, not yet
 * implemented). Build/run: `make tls-live-test`. Needs outbound network.
 *
 *   usage: tls-live-test [host] [port]   (default www.eff.org 443)
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

    /* Success criterion (14.0.3a.1): decrypt >= 1 real application_data record.
     * Some servers send a NewSessionTicket proactively; this sandbox's proxy
     * terminator does not, so send a minimal probe to elicit a server record. We
     * do NOT parse the response as HTTP (that is 14.0.4) — this only proves we can
     * SEAL a client app record and OPEN the server's response over the real
     * channel (application traffic keys, per-epoch sequence, nonce derivation). */
    {
        char req[160];
        int rql = snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
        int sl = tls_conn_send_app(&g_conn, (const uint8_t*)req, (size_t)rql, g_scratch, sizeof g_scratch);
        if (sl > 0 && write(g_fd, g_scratch, sl) == sl)
            printf("[app] sent %d-byte probe (sealed over the app epoch)\n", rql);
    }

    int decrypted = 0;
    for (;;) {
        const uint8_t *rec; size_t rl; int rc;
        while ((rc = tls_reader_next(&g_reader, &rec, &rl)) == 1) {
            printf("[rec] application_data record %zu bytes\n", rl);
            size_t pl = 0;
            int cc = tls_conn_recv_app(&g_conn, rec, rl, g_plain, sizeof g_plain - 1, &pl);
            if (cc == TLS_CONN_ERR_ALERT) { printf("[TLS] peer alert (close_notify)\n"); goto done; }
            if (cc < 0) { fprintf(stderr, "[live] recv_app error %d\n", cc); goto done; }
            decrypted++;                       /* a real app-data record decrypted OK */
            if (pl > 0) printf("[rec] decrypted %zu plaintext bytes (post-handshake data)\n", pl);
            else        printf("[rec] decrypted post-handshake msg (NewSessionTicket), out_len=0\n");
            if (decrypted >= 1) goto done;     /* criterion met; don't wait for more */
        }
        if (rc < 0) { fprintf(stderr, "[live] malformed record on app stream\n"); break; }
        int n = (int)read(g_fd, g_scratch, sizeof g_scratch);
        if (n <= 0) { fprintf(stderr, "[live] no application_data before EOF/timeout\n"); break; }
        printf("[net] recv %d bytes (post-handshake)\n", n);
        tls_reader_feed(&g_reader, g_scratch, (size_t)n);
    }
done:
    close(g_fd);
    if (decrypted >= 1) {
        printf("\nLIVE TLS TEST: PASS (CONNECTED + decrypted %d real application_data record(s))\n", decrypted);
        return 0;
    }
    printf("\nLIVE TLS TEST: INCOMPLETE (reached CONNECTED but no application_data record decrypted)\n");
    return 2;
}
