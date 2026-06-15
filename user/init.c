/* init: PID 1. Starts system services and supervises children.
 *
 *   kernel -> init -> { logger (daemon), shell }
 *
 * If the logger dies it is restarted; when the shell exits, init shuts down. */
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
            printf("[init] shell exited (%d); shutting down\n", st);
            break;
        }
        if (pid == logpid) {
            printf("[init] logger died; restarting\n");
            logpid = start("/disk/LOGGER.ELF");
        }
    }
    return 0;
}
