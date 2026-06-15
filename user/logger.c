/* logger: a system log daemon. Registers as "log" and prints messages it
 * receives over IPC, tagged with the sender's pid. */
#include "libc.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (svc_register("log") != 0) {
        fprintf(2, "logger: failed to register\n");
        return 1;
    }
    printf("[logger] ready (pid %d), registered as \"log\"\n", getpid());

    char buf[256];
    int from;
    for (;;) {
        int n = msgrecv(buf, sizeof(buf) - 1, &from);
        if (n < 0)
            continue;
        buf[n] = '\0';
        printf("[log] (pid %d) %s\n", from, buf);
    }
    return 0;
}
