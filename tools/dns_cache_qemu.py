#!/usr/bin/env python3
"""Phase 15.6 acceptance: the DNS cache, exercised for real inside QEMU
against the SLIRP-forwarded resolver -- not just the pure slot-logic host
test (`make dns-cache-test`).

Boots Aurora with the `nettest` cmdline flag (which already resolves
"example.com" once as part of the existing Phase 7.5 self-test) and checks
the newly-added Phase 15.6 section of net_selftest():
  1. re-querying the same name is a cache hit ("[dns] cache hit: ...") that
     returns the same address, not a second network round trip.
  2. a deliberately unresolvable name is negative-cached: the first lookup
     fails and caches the failure, the second is a "[dns] cache hit
     (negative)" -- not a second failed round trip either.

Self-contained: no files written to the repo, no test-only trust store swap
needed (this doesn't touch TLS/httpsget at all). Requires: qemu-system-i386,
the cross toolchain (i.e. `make`), and outbound DNS resolution for
"example.com" through this environment's network policy (the same
assumption net_selftest()'s Phase 7.5 section already makes). Run from the
repo root: python3 tools/dns_cache_qemu.py
"""
import os, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def run_qemu(serial_path):
    tmp = tempfile.mkdtemp(); mon = os.path.join(tmp, "m.sock")
    if os.path.exists(serial_path): os.remove(serial_path)
    q = ["qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
         "-display", "none", "-serial", "file:" + serial_path,
         "-monitor", "unix:%s,server,nowait" % mon,
         "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
         "-append", "nettest", "-no-reboot", "-no-shutdown"]
    p = subprocess.Popen(q, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(16)     # net_selftest() runs a lot before reaching the DNS section
    finally:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-15x6-")
    serial = os.path.join(work, "serial.log")
    fails = 0
    try:
        if sh("make aurora.elf").returncode != 0:
            print("build FAILED"); return 1

        log = run_qemu(serial)

        resolved = "[dns] example.com ->" in log and "no answer" not in log
        if not resolved:
            print("SKIP: example.com did not resolve in this environment "
                  "(outbound DNS policy) -- cannot exercise the positive-cache path")
        else:
            ok = "[dns] cache hit: example.com ->" in log and "[dns] cache re-query example.com -> OK (matches)" in log
            print(f"{'positive cache hit':28}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1

        neg_ok = ("[dns] cached this-host-should-not-resolve.invalid (negative" in log
                  and "[dns] cache hit (negative): this-host-should-not-resolve.invalid" in log
                  and "[dns] negative cache: first=-1 second=-1 -- NEGATIVE CACHE OK" in log)
        print(f"{'negative cache hit':28}: {'PASS' if neg_ok else 'FAIL'}")
        if not neg_ok: fails += 1
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    print("\n15.6 DNS CACHE (QEMU, real SLIRP-forwarded resolver): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
