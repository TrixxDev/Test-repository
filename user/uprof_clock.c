/* Real clock for user/uprof.h's cprof_now_us(), linked only into actual
 * userspace binaries (httpsget.elf, tlsconnect.elf) -- host test tools
 * define their own stub instead of linking this file (see uprof.h). */
#include "uprof.h"
#include "libc.h"

uint64_t cprof_now_us(void)
{
    return (uint64_t)perf_us();
}
