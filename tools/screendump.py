#!/usr/bin/env python3
"""Boot AuroraOS headless in QEMU and capture the live framebuffer to a PNG.

This makes the GUI verifiable without a display. It boots the real kernel with
the Bochs-VBE framebuffer path (`-append vbe`), waits for the window server to
come up, optionally injects keystrokes through the QEMU monitor, then asks the
monitor to `screendump` the actual framebuffer and converts the PPM to PNG.

Usage:
    screendump.py <kernel.elf> <disk.img> <out.png>
                  [--keys h,e,l,l,o,spc,w,o,r,l,d] [--delay 6] [--serial FILE]

Key names are QEMU monitor keynames (letters/digits as-is; `spc`, `ret`, etc.).
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def mon_connect(path, tries=50):
    for _ in range(tries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("could not connect to QEMU monitor at " + path)


def mon_cmd(s, cmd, settle=0.25):
    s.sendall((cmd + "\n").encode())
    time.sleep(settle)
    try:
        s.setblocking(False)
        s.recv(65536)
    except BlockingIOError:
        pass
    finally:
        s.setblocking(True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("disk")
    ap.add_argument("out")
    ap.add_argument("--keys", default="", help="comma-separated QEMU keynames")
    ap.add_argument("--delay", type=float, default=6.0, help="boot settle seconds")
    ap.add_argument("--serial", default="", help="write the serial log here too")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="aurora-shot-")
    sock = os.path.join(tmp, "mon.sock")
    serial = args.serial or os.path.join(tmp, "serial.log")
    ppm = os.path.join(tmp, "screen.ppm")

    qemu = [
        "qemu-system-i386", "-kernel", args.kernel, "-m", "64M",
        "-drive", "file=%s,format=raw,if=ide" % args.disk,
        "-vga", "std", "-append", "vbe", "-display", "none",
        "-serial", "file:" + serial,
        "-monitor", "unix:%s,server,nowait" % sock,
        "-no-reboot", "-no-shutdown",
    ]
    proc = subprocess.Popen(qemu, stderr=subprocess.DEVNULL)
    try:
        time.sleep(args.delay)
        s = mon_connect(sock)
        time.sleep(0.3)
        try:
            s.setblocking(False); s.recv(65536)
        except BlockingIOError:
            pass
        finally:
            s.setblocking(True)
        if args.keys:
            for k in [k for k in args.keys.split(",") if k]:
                mon_cmd(s, "sendkey " + k)
            time.sleep(0.5)
        mon_cmd(s, "screendump " + ppm, settle=1.0)
        s.close()
    finally:
        try:
            s2 = mon_connect(sock, tries=5)
            mon_cmd(s2, "quit", settle=0.2)
            s2.close()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not os.path.exists(ppm):
        sys.stderr.write("screendump failed (no PPM produced)\n")
        if os.path.exists(serial):
            sys.stderr.write("--- last serial lines ---\n")
            sys.stderr.write("".join(open(serial).readlines()[-15:]))
        sys.exit(1)

    subprocess.check_call(
        [sys.executable, os.path.join(HERE, "ppm2png.py"), ppm, args.out])
    # Surface the key serial markers so the caller sees the live evidence.
    if os.path.exists(serial):
        for line in open(serial):
            if any(m in line for m in ("[fb]", "[wm]", "[term]")):
                sys.stdout.write("  " + line.rstrip() + "\n")
    print("Wrote %s" % args.out)


if __name__ == "__main__":
    main()
