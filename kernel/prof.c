#include "prof.h"

struct kernel_prof g_kprof;

void kprof_get(struct kernel_prof *out)
{
    if (out)
        *out = g_kprof;
}
