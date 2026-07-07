#!/usr/bin/env python3
"""Phase 18.4.1 acceptance: TCP actually pipelines several segments in
flight instead of the old single-segment stop-and-wait model.

`user/sendwintest.c` connects over plain TCP (no TLS -- this is testing the
transport layer itself, not the crypto above it), writes a body several
times larger than one segment (TCP_TX_MAX = 1400 bytes) in ONE write() call,
then reads back net/tcp.c's own tcp_stats.max_inflight counter (Phase
18.4.1's new observability hook: the highest number of unacknowledged
segments any connection has ever had queued at once) and asserts it's > 1 --
direct, unambiguous proof of pipelining, not just "it didn't crash."

The peer here is a raw Python socket server (no TLS, no HTTP) that just
accepts one connection and reads everything sent to it, confirming the
exact byte count and content arrived intact despite being sent as several
segments genuinely in flight together.

Run from the repo root: python3 tools/tcp_sendwin_qemu.py
"""
import os, socket, subprocess, sys, tempfile, threading, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NBYTES = 20000    # ~15 segments at TCP_TX_MAX=1400 bytes/segment


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def start_server(port, result):
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
        except (socket.timeout, OSError) as e:
            result["error"] = str(e)
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


def run_qemu(serial_path, typed_cmd, wait_s=40):
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
        km = {" ": "spc", ".": "dot", "/": "slash"}
        for ch in typed_cmd:
            s.sendall(("sendkey " + km.get(ch, ch) + "\n").encode()); time.sleep(0.12)
        s.sendall(b"sendkey ret\n"); time.sleep(wait_s)
        s.sendall(b"quit\n"); time.sleep(0.3); s.close()
    finally:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-18x4x1-")
    serial = os.path.join(work, "serial.log")
    fails = 0
    srv = None
    try:
        if sh("make aurora.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        result = {}
        srv = start_server(9100, result)

        log = run_qemu(serial, "sendwin 10.0.2.2 9100 %d" % NBYTES)

        expected = bytes((ord('A') + (i % 26)) for i in range(NBYTES))
        received = result.get("received", b"")

        checks = [
            ("server accepted the connection", result.get("connected") is True),
            ("server received the exact byte count", len(received) == NBYTES),
            ("server received the exact content (no corruption across pipelined segments)",
             received == expected),
            ("client log: connected", "connected: PASS" in log),
            ("client log: write() sent all requested bytes in one call", "PASS (got %d)" % NBYTES in log),
            ("client log: max_inflight > 1 (real pipelining, not stop-and-wait)",
             "more than one segment was ever in flight at once" in log and
             "more than one segment was ever in flight at once (real pipelining, not stop-and-wait): PASS" in log),
            ("client log: final ALL PASS", "18.4.1 TCP SEND WINDOW: ALL PASS" in log),
        ]

        for name, ok in checks:
            print(f"{name:85}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1

        import re
        m = re.search(r"max_inflight = (\d+)", log)
        if m:
            print(f"(observed max_inflight = {m.group(1)})")
    finally:
        if srv:
            try: srv.close()
            except OSError: pass
        shutil.rmtree(work, ignore_errors=True)
    print("\n18.4.1 TCP SEND WINDOW -- multiple segments in flight (QEMU, real server): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
