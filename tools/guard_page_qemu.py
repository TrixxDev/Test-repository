"""Phase 18.5.6 acceptance: kernel stack guard pages.

Types `kstktest`, which calls SYS_DEBUG_KSTACK_OVERFLOW to deliberately
recurse past its own kernel stack. Before this phase, an overflow like this
(the same shape as the real fs/fat32.c cbuf bug, docs/SECURITY.md "Step
18.5") never faulted at all -- it silently overwrote whatever kmalloc'd
heap memory happened to sit next to the stack. Now the very first
out-of-bounds write should hit the unmapped guard page and halt with a
diagnostic instead of a generic page fault, a silent triple-fault reset, or
continuing to run without ever noticing.

Two distinct diagnostics are both a PASS, and empirically depend on exactly
how the overflow lands: a tight, one-push-at-a-time recursion (this test)
reliably escalates to a double fault (the CPU's own same-privilege exception
delivery re-faults trying to use the already-broken stack, handled by
arch/i386/gdt.c's df_tss task gate instead of the ordinary vector-14 path),
printing "DOUBLE FAULT". A less aggressive overflow that doesn't leave ESP
sitting exactly on the boundary would instead hit vector 14's own handler
directly, printing "KERNEL STACK OVERFLOW". Either is the guard page working;
neither appearing is the failure.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu_serial import run_qemu_serial


def main():
    log = run_qemu_serial("kstktest", wait_s=20)

    guard_fired = ("KERNEL STACK OVERFLOW" in log) or ("DOUBLE FAULT" in log)
    checks = [
        ("guard page fired (direct diagnostic or double-fault escalation)", guard_fired),
        ("no unrelated CPU exception fallthrough", "*** CPU EXCEPTION:" not in log),
        ("test program actually ran", "[kstacktest] about to deliberately overflow" in log),
        ("did NOT return from debug_kstack_overflow() (would mean no fault at all)",
         "FAIL: debug_kstack_overflow() returned" not in log),
    ]

    fails = 0
    for name, ok in checks:
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            fails += 1

    if fails:
        print("\n--- full log ---")
        print(log)

    print(f"\n18.5.6 GUARD PAGES: {'ALL PASS' if fails == 0 else 'SOME FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
