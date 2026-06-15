/* init: PID 1. Starts services, adopts and reaps orphaned children, and
 * performs a graceful shutdown when the shell exits.
 *
 * Services (logger, netd) run as root (uid 0); the interactive shell — and so
 * everything it launches — runs as an unprivileged user (uid 1000). */
#include "libc.h"

#define UID_USER 1000

static int start_uid(const char *path, int uid)
{
    int pid = fork();
    if (pid == 0) {
        if (uid >= 0)
            setuid(uid);
        char *argv[] = { (char *)path, 0 };
        execv(path, argv);
        _exit(127);
    }
    return pid;
}

static int start(const char *path) { return start_uid(path, -1); }

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("[init] AuroraOS init (pid %d, uid %d)\n", getpid(), getuid());

    int logpid = start("/disk/LOGGER.ELF");
    int netpid = start("/disk/NETD.ELF");
    int shpid  = start_uid("/disk/SH.ELF", UID_USER);
    (void)logpid;

    for (;;) {
        int st;
        int pid = wait(&st);

        if (pid == shpid) {
            /* Shut down: ask the logger to stop, force-kill the rest, reap all. */
            printf("[init] shell exited (%d); shutting down services\n", st);
            int lp = svc_lookup("log");
            if (lp > 0)
                msgsend(lp, "shutdown", 8);
            for (volatile int d = 0; d < 2000000; d++) ;   /* let it drain */
            if (netpid > 0) kill(netpid);
            if (lp > 0)     kill(lp);
            int s;
            while (wait(&s) > 0)                            /* reap survivors */
                ;
            break;
        }

        if (pid == logpid) {
            printf("[init] logger died; restarting\n");
            logpid = start("/disk/LOGGER.ELF");
            continue;
        }
        if (pid == netpid) {
            printf("[init] netd died; restarting\n");
            netpid = start("/disk/NETD.ELF");
            continue;
        }

        /* An orphan adopted by init finished. */
        printf("[init] reaped adopted child pid %d (exit %d)\n", pid, st);
    }
    return 0;
}
