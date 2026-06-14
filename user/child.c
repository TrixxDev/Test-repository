/* child: the exec() target. Prints, does a little work, exits with code 42. */
#include "ulib.h"

void _start(void)
{
    uputint("[child:exec] now running CHILD.ELF, pid", sys_getpid());
    uputs("[child:exec] doing work, then exit(42)\n");

    for (volatile int i = 0; i < 3000000; i++)
        ;

    sys_exit(42);
}
