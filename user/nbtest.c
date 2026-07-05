/* Phase 18.2 acceptance: O_NONBLOCK + fcntl() + EAGAIN, exercised on a real
 * pipe inside the running kernel (this can't be host-tested -- it needs the
 * real scheduler, VFS and syscall path). */
#include "libc.h"

int main(void)
{
    int fds[2];
    if (pipe(fds) != 0) {
        printf("pipe() failed\n");
        return 1;
    }
    int rfd = fds[0], wfd = fds[1];
    int fails = 0;

    int fl = fcntl(rfd, F_GETFL, 0);
    printf("a fresh pipe fd is blocking by default (F_GETFL == 0): %s\n", fl == 0 ? "PASS" : "FAIL");
    if (fl != 0) fails++;

    int rc = fcntl(rfd, F_SETFL, O_NONBLOCK);
    printf("fcntl(F_SETFL, O_NONBLOCK) returns 0: %s\n", rc == 0 ? "PASS" : "FAIL");
    if (rc != 0) fails++;

    fl = fcntl(rfd, F_GETFL, 0);
    printf("F_GETFL now reports O_NONBLOCK: %s\n", (fl & O_NONBLOCK) ? "PASS" : "FAIL");
    if (!(fl & O_NONBLOCK)) fails++;

    char buf[16];
    int n = read(rfd, buf, sizeof(buf));
    printf("non-blocking read on an empty pipe (writer still open) returns -EAGAIN immediately: %s (got %d)\n",
           n == -EAGAIN ? "PASS" : "FAIL", n);
    if (n != -EAGAIN) fails++;

    write(wfd, "hi", 2);
    n = read(rfd, buf, sizeof(buf));
    printf("non-blocking read succeeds once data is actually there: %s (got %d bytes)\n",
           n == 2 ? "PASS" : "FAIL", n);
    if (n != 2) fails++;

    rc = fcntl(rfd, F_SETFL, 0);
    fl = fcntl(rfd, F_GETFL, 0);
    printf("fcntl(F_SETFL, 0) clears O_NONBLOCK: %s\n", (rc == 0 && fl == 0) ? "PASS" : "FAIL");
    if (!(rc == 0 && fl == 0)) fails++;

    close(wfd);
    n = read(rfd, buf, sizeof(buf));
    printf("blocking read on a pipe with no writers left returns EOF (0), not a hang: %s (got %d)\n",
           n == 0 ? "PASS" : "FAIL", n);
    if (n != 0) fails++;

    printf("\n18.2 NON-BLOCKING I/O: %s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
    return fails ? 1 : 0;
}
