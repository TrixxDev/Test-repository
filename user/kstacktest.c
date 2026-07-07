/* Phase 18.5.6 acceptance: deliberately overflow this thread's kernel stack
 * (via SYS_DEBUG_KSTACK_OVERFLOW) to confirm its guard page actually halts
 * the machine with a "KERNEL STACK OVERFLOW" diagnostic instead of silently
 * corrupting adjacent heap memory the way the fs/fat32.c cbuf bug did (see
 * docs/SECURITY.md "Step 18.5"). This call never returns -- the pass/fail
 * check is tools/guard_page_qemu.py grepping the serial log for that
 * message, not this program's own exit code. */
#include "libc.h"

int main(void)
{
    printf("[kstacktest] about to deliberately overflow the kernel stack...\n");
    debug_kstack_overflow();
    printf("[kstacktest] FAIL: debug_kstack_overflow() returned -- guard page did not catch it\n");
    return 1;
}
