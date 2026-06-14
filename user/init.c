/* init: the first user process. Demonstrates fork + exec + wait + exit codes. */
#include "ulib.h"

void _start(void)
{
    uputint("[init] running, pid", sys_getpid());
    uputs("[init] forking a child...\n");

    int pid = sys_fork();
    if (pid == 0) {
        /* Child: replace our image with CHILD.ELF. */
        uputs("[child] fork returned 0, calling exec(/disk/CHILD.ELF)\n");
        sys_exec("/disk/CHILD.ELF");
        uputs("[child] exec failed!\n");
        sys_exit(127);
    } else {
        uputint("[init] fork returned child pid", pid);
        uputs("[init] waiting for child...\n");

        int status = -1;
        int reaped = sys_wait(&status);
        uputint("[init] reaped child pid", reaped);
        uputint("[init] child exit code", status);

        uputs("[init] exiting with code 0\n");
        sys_exit(0);
    }
}
