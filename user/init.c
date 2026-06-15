/* init: PID 1. Starts services, adopts and reaps orphaned children, and
 * performs a graceful shutdown when the shell exits. */
#include "libc.h"

static int start(const char *path)
{
    int pid = fork();
    if (pid == 0) {
        char *argv[] = { (char *)path, 0 };
        execv(path, argv);
        _exit(127);
    }
    return pid;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("[init] AuroraOS init (pid %d)\n", getpid());

    int logpid = start("/disk/LOGGER.ELF");
    int shpid  = start("/disk/SH.ELF");

    for (;;) {
        int st;
        int pid = wait(&st);

        if (pid == shpid) {
            /* Graceful shutdown: ask services to stop, wait, then force-kill. */
            printf("[init] shell exited (%d); stopping services\n", st);
            int lp = svc_lookup("log");
            if (lp > 0) {
                msgsend(lp, "shutdown", 8);
                for (int i = 0; i < 50; i++) {
                    int s;
                    int r = wait_nohang(&s);
                    if (r == lp) { printf("[init] logger stopped gracefully\n"); lp = 0; break; }
                    for (volatile int d = 0; d < 200000; d++) ;
                }
                if (lp > 0) {           /* still alive -> force kill */
                    printf("[init] force-killing logger (pid %d)\n", lp);
                    kill(lp);
                    int s; wait(&s);
                }
            }
            break;
        }

        if (pid == logpid) {
            printf("[init] logger died; restarting\n");
            logpid = start("/disk/LOGGER.ELF");
            continue;
        }

        /* An orphan adopted by init finished. */
        printf("[init] reaped adopted child pid %d (exit %d)\n", pid, st);
    }
    return 0;
}
