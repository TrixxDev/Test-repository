#!/usr/bin/env python3
"""Phase 18.5.2 acceptance: proves the new kernel-wide profiling counters
(SYS_PROFSTAT) actually move when real work happens, not just that the
syscall compiles and returns zeros.

Drives one QEMU boot through a small real workload exercising every counter
tracked so far:
  - `cat` an existing file on the FAT32 disk -> fat_read_calls
  - `sendwin` against a real TCP sink         -> tcp_input_calls, tcp_tick_calls
                                                 (18.4.1's own pipelining test,
                                                 reused here as a real network
                                                 workload, not just for its own
                                                 pipelining assertion)
  - all of the above, plus normal boot        -> sched_switches, wait_blocks,
                                                 memcpy_calls/memcpy_bytes
then reads `profstat` and checks every counter is nonzero.

fat_write_calls is NOT exercised here: `save <path> <text>` followed by
process exit reliably crashes the kernel (CPU EXCEPTION: Debug, eip pointing
into the written string's own bytes -- looks like a corrupted return address)
independent of anything in Phase 18.5.2 -- confirmed still reproducing on a
clean pre-18.5.2 worktree (commit 1d77d1a) with fat32.c/scheduler.c/etc.
completely unmodified. That's a genuine, separate, pre-existing bug (this
project apparently never had an automated test drive `save` through a full
write+exit cycle before), not something this phase's instrumentation caused
or should paper over by "fixing" it here. fat_write's timing wrapper is
structurally identical to fat_read's (see fs/fat32.c) and reviewed by hand;
exercising it for real is left for whoever investigates that crash.

Run from the repo root: python3 tools/prof_qemu.py
"""
import os, re, socket, subprocess, sys, tempfile, threading, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NBYTES = 20000

KEYMAP = {" ": "spc", ".": "dot", "/": "slash"}


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def start_tcp_sink(port, result):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for attempt in range(20):
        try:
            raw.bind(("0.0.0.0", port)); break
        except OSError:
            if attempt == 19: raise
            time.sleep(0.2)
    raw.listen(4)

    def handle(conn):
        result["connected"] = True
        conn.settimeout(30)
        buf = b""
        try:
            while len(buf) < NBYTES:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, OSError):
            pass
        result["received"] = buf
        try: conn.close()
        except OSError: pass

    def loop():
        try:
            conn, _ = raw.accept()
        except OSError:
            return
        handle(conn)

    threading.Thread(target=loop, daemon=True).start()
    return raw


def run_qemu(serial_path, commands, per_cmd_wait):
    tmp = tempfile.mkdtemp(); mon = os.path.join(tmp, "m.sock")
    if os.path.exists(serial_path): os.remove(serial_path)
    q = ["qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
         "-drive", "file=disk.img,format=raw,if=ide", "-display", "none",
         "-serial", "file:" + serial_path, "-monitor", "unix:%s,server,nowait" % mon,
         "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
         "-no-reboot", "-no-shutdown"]
    p = subprocess.Popen(q, cwd=ROOT, stderr=subprocess.DEVNULL)
    try:
        s = None
        for _ in range(80):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(mon); break
            except OSError: time.sleep(0.1)
        time.sleep(7)
        for cmd, wait_s in zip(commands, per_cmd_wait):
            for ch in cmd:
                s.sendall(("sendkey " + KEYMAP.get(ch, ch) + "\n").encode()); time.sleep(0.1)
            s.sendall(b"sendkey ret\n"); time.sleep(wait_s)
        s.sendall(b"quit\n"); time.sleep(0.3); s.close()
    finally:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-18x5x2-")
    serial = os.path.join(work, "serial.log")
    fails = 0
    srv = None
    try:
        # disk.img's Makefile rule only depends on the ELF/script inputs, not
        # on itself -- rebuild it fresh so this run isn't affected by
        # whatever state a previous manual/automated session left on it.
        disk_path = os.path.join(ROOT, "disk.img")
        if os.path.exists(disk_path):
            os.remove(disk_path)
        if sh("make aurora.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        result = {}
        srv = start_tcp_sink(9100, result)

        commands = [
            "cat /disk/about.txt",
            "sendwin 10.0.2.2 9100 %d" % NBYTES,
            "profstat",
        ]
        waits = [3, 40, 3]

        log = run_qemu(serial, commands, waits)

        def field(name):
            m = re.search(name + r"=(\d+)", log)
            return int(m.group(1)) if m else None

        counters = {
            "sched_switches": field("sched_switches"),
            "wait_blocks": field("wait_blocks"),
            "tcp_input_calls": field("tcp_input_calls"),
            "tcp_tick_calls": field("tcp_tick_calls"),
            "fat_read_calls": field("fat_read_calls"),
            "fat_write_calls": field("fat_write_calls"),
            "memcpy_calls": field("memcpy_calls"),
            "memcpy_bytes": field("memcpy_bytes"),
        }
        # fat_write_calls is deliberately not exercised (see module docstring
        # for why) -- 0 is the expected, correct value here, not a failure.
        must_be_positive = [k for k in counters if k != "fat_write_calls"]

        checks = [
            ("sendwin: TCP sink received the exact byte count",
             result.get("received") is not None and len(result.get("received", b"")) == NBYTES),
            ("profstat: all fields parsed", all(v is not None for v in counters.values())),
        ]
        for name in must_be_positive:
            count = counters[name]
            checks.append((f"profstat: {name} > 0 (real work moved it)",
                           count is not None and count > 0))
        checks.append(("profstat: fat_write_calls == 0 (not exercised this run, see docstring)",
                       counters["fat_write_calls"] == 0))

        for name, ok in checks:
            print(f"{name:70}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1

        if all(v is not None for v in counters.values()):
            print("\nobserved counters:")
            for k, v in counters.items():
                print(f"  {k} = {v}")
    finally:
        if srv:
            try: srv.close()
            except OSError: pass
        shutil.rmtree(work, ignore_errors=True)
    print("\n18.5.2 KERNEL PROFILING COUNTERS (QEMU, real workload): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
