"""Phase 19.2 acceptance: stack canaries (both layers).

Types `canaryt`, which first smashes a userspace stack buffer in a fork()ed
child -- user/libc/ssp.c's __stack_chk_fail() must abort JUST that process
with exit status 134 while the OS keeps running -- and then invokes
SYS_DEBUG_STACK_SMASH, which overruns a kernel frame buffer by 64 bytes:
enough to hit the compiler-inserted canary, deliberately nowhere near the
guard page, so a halt here is -fstack-protector-strong firing on its own
(arch/i386/stack_protector.c), not Phase 18.5.6's guard page.

Distinct from tools/guard_page_qemu.py on purpose: that test proves the
PAST-the-stack boundary layer; this one proves the IN-frame corruption
layer. A regression in either shows up in exactly one of the two tests.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu_serial import run_qemu_serial


def main():
    log = run_qemu_serial("canaryt", wait_s=20)

    checks = [
        ("userspace canary fired (child aborted with exit status 134)",
         "child exit status=134" in log),
        ("OS survived the userspace smash (phase 2 was reached)",
         "phase 2: kernel canary" in log),
        ("kernel canary fired (KERNEL STACK SMASHING DETECTED)",
         "KERNEL STACK SMASHING DETECTED" in log),
        ("kernel halt was the canary, not a fault (no exception/guard-page text)",
         "*** CPU EXCEPTION:" not in log and "KERNEL STACK OVERFLOW" not in log
         and "DOUBLE FAULT" not in log),
        ("no FAIL lines (neither smash survived unnoticed)",
         "FAIL:" not in log),
    ]

    fails = 0
    for name, ok in checks:
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            fails += 1

    if fails:
        print("\n--- full log ---")
        print(log)

    print(f"\n19.2 STACK CANARIES: {'ALL PASS' if fails == 0 else 'SOME FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
