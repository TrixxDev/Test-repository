/* Phase 18.3 acceptance: wait_events() -- a single call waiting on several
 * different fd *types* at once (a pipe and the console here), with a real
 * millisecond timeout bound (unlike the older poll(), which just blocks
 * forever for any nonzero timeout). Needs the real kernel, not host-testable. */
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

    struct pollfd pfd[2];
    pfd[0].fd = rfd; pfd[0].events = POLLIN;
    pfd[1].fd = 0;   pfd[1].events = POLLIN;   /* console (stdin) */

    int n = wait_events(pfd, 2, 0);
    printf("nothing ready anywhere, timeout=0 returns 0 immediately: %s (got %d)\n",
           n == 0 ? "PASS" : "FAIL", n);
    if (n != 0) fails++;

    n = wait_events(pfd, 2, 150);
    printf("nothing ready, a bounded 150ms timeout returns 0 (not a hang): %s (got %d)\n",
           n == 0 ? "PASS" : "FAIL", n);
    if (n != 0) fails++;

    int pid = fork();
    if (pid == 0) {
        msleep(200);
        write(wfd, "hi", 2);
        _exit(0);
    }

    pfd[0].revents = pfd[1].revents = 0;
    n = wait_events(pfd, 2, 5000);
    int pipe_ready = (pfd[0].revents & POLLIN) != 0;
    int console_ready = (pfd[1].revents & POLLIN) != 0;
    printf("waiting on a pipe AND the console together wakes specifically for the pipe: %s (n=%d pipe=%d console=%d)\n",
           (n >= 1 && pipe_ready && !console_ready) ? "PASS" : "FAIL", n, pipe_ready, console_ready);
    if (!(n >= 1 && pipe_ready && !console_ready))
        fails++;

    char buf[16];
    int got = read(rfd, buf, sizeof(buf));
    printf("the data that made it ready is actually there to read: %s (got %d bytes)\n",
           got == 2 ? "PASS" : "FAIL", got);
    if (got != 2) fails++;

    int st;
    wait(&st);

    printf("\n18.3 EVENT WAITING: %s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
    return fails ? 1 : 0;
}
