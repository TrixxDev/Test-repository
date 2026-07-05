/* Phase 18.4.1 acceptance: proves TCP sends actually pipeline several
 * segments in flight instead of stop-and-wait. Usage:
 *   sendwintest <host> <port> <bytes>
 * Connects, writes `bytes` of data in one write() call (several TCP
 * segments' worth), then checks tcpstat().max_inflight > 1 -- direct,
 * unambiguous proof that more than one unacknowledged segment was queued
 * at once, which a single-segment stop-and-wait sender could never do. */
#include "libc.h"

int main(int argc, char **argv)
{
    if (argc < 4) {
        printf("usage: sendwintest <host> <port> <bytes>\n");
        return 1;
    }
    const char *host = argv[1];
    int port = 0;
    for (const char *p = argv[2]; *p >= '0' && *p <= '9'; p++) port = port * 10 + (*p - '0');
    int nbytes = 0;
    for (const char *p = argv[3]; *p >= '0' && *p <= '9'; p++) nbytes = nbytes * 10 + (*p - '0');

    int fails = 0;

    int fd = inet_socket();
    if (fd < 0) { printf("inet_socket failed\n"); return 1; }
    int rc = inet_connect(fd, host, port);
    printf("connected: %s\n", rc == 0 ? "PASS" : "FAIL");
    if (rc != 0) { fails++; close(fd); goto done; }

    {
        char *buf = (char *)malloc((unsigned)nbytes);
        for (int i = 0; i < nbytes; i++)
            buf[i] = (char)('A' + (i % 26));

        int n = write(fd, buf, nbytes);
        printf("write() sent all %d requested bytes in one call: %s (got %d)\n",
               nbytes, n == nbytes ? "PASS" : "FAIL", n);
        if (n != nbytes) fails++;
        free(buf);

        struct tcp_stats ts;
        tcpstat(&ts);
        printf("tcpstat: max_inflight = %u\n", ts.max_inflight);
        printf("more than one segment was ever in flight at once (real pipelining, not stop-and-wait): %s\n",
               ts.max_inflight > 1 ? "PASS" : "FAIL");
        if (!(ts.max_inflight > 1)) fails++;

        close(fd);
    }

done:
    printf("\n18.4.1 TCP SEND WINDOW: %s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
    return fails ? 1 : 0;
}
