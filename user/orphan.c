/* orphan: demonstrates reparenting. The parent forks a child and exits
 * immediately; the child outlives it, is adopted by init, and is reaped there. */
#include "libc.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    int pid = fork();
    if (pid == 0) {
        /* Child: wait a bit so the parent exits first, then finish. */
        for (volatile int i = 0; i < 12000000; i++)
            ;
        printf("[orphan-child] alive as pid %d; parent gone -> adopted by init\n",
               getpid());
        return 7;
    }

    printf("[orphan-parent] exiting now, leaving child %d orphaned\n", pid);
    return 0;
}
