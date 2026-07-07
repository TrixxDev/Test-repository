/* echosrv: a loopback echo server (Phase 8A.3).
 *
 * Validates the whole socket path: socket -> bind -> listen -> accept (brokered
 * by netd), then poll + recv + send on the connected endpoint. Echoes each
 * chunk back until the client closes, then waits for the next client. */
#include "libc.h"
#include "net.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    int s = socket(AF_LOOPBACK, SOCK_STREAM);
    if (s < 0) { fprintf(2, "echosrv: socket failed\n"); return 1; }
    if (bind(s, PORT_ECHO) != 0) { fprintf(2, "echosrv: bind failed\n"); return 1; }
    listen(s);
    printf("[echosrv] listening on loopback port %d (pid %d)\n", PORT_ECHO, getpid());

    for (;;) {
        int c = accept(PORT_ECHO);
        if (c < 0) { fprintf(2, "echosrv: accept failed\n"); break; }
        printf("[echosrv] client connected (fd %d)\n", c);

        char buf[256];
        for (;;) {
            struct pollfd pfd = { c, POLLIN, 0 };
            if (poll(&pfd, 1, -1) < 0)
                break;
            int n = recv(c, buf, sizeof(buf));
            if (n <= 0)                 /* 0 = client closed, <0 = error */
                break;
            send(c, buf, n);            /* echo it straight back */
        }
        printf("[echosrv] client disconnected\n");
        close(c);
    }
    close(s);
    return 0;
}
