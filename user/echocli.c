/* echocli: a loopback echo client (Phase 8A.3).
 *
 * Connects to the echo server through netd, sends a message, and prints what
 * comes back. Usage: echocli [message] */
#include "libc.h"
#include "net.h"

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

int main(int argc, char **argv)
{
    const char *msg = (argc > 1) ? argv[1] : "hello aurora";

    int c = socket(AF_LOOPBACK, SOCK_STREAM);
    if (c < 0) { fprintf(2, "echocli: socket failed\n"); return 1; }

    /* The server may not have bound its port yet; retry a connect refusal. */
    int r = -1;
    for (int tries = 0; tries < 20 && r != 0; tries++) {
        r = connect(c, PORT_ECHO);
        if (r != 0)
            for (volatile int d = 0; d < 200000; d++) ;
    }
    if (r != 0) { fprintf(2, "echocli: connect failed\n"); close(c); return 1; }

    int len = slen(msg);
    send(c, msg, len);
    printf("[echocli] sent: %s\n", msg);

    char buf[256];
    int n = recv(c, buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("[echocli] echo: %s\n", buf); }
    else        printf("[echocli] no echo (n=%d)\n", n);

    close(c);
    return 0;
}
