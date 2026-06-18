#!/usr/bin/env python3
"""Boot AuroraOS headless in QEMU and capture the live framebuffer to a PNG.

This makes the GUI verifiable without a display. It boots the real kernel with
the Bochs-VBE framebuffer path (`-append vbe`), waits for the window server to
come up, optionally injects keyboard / mouse input, then asks the QEMU monitor
to `screendump` the actual framebuffer and converts the PPM to PNG.

Usage:
    screendump.py <kernel.elf> <disk.img> <out.png>
                  [--keys h,e,l,l,o,spc,w,o,r,l,d]
                  [--mouse "move:-200,150;click;abs:16383,16383;wait:1;key:ret"]
                  [--append abs] [--delay 6] [--serial FILE]

Keyboard key names are QEMU monitor keynames (letters/digits as-is; `spc`, `ret`).
Mouse steps (`;`-separated):
    move:DX,DY  relative motion (PS/2)        click / down / up  left button
    abs:AX,AY   absolute pointer 0..32767     wait:SEC           pause mid-script
    key:NAME    send a key (interleaved with clicks via the monitor)
`--append WORDS` adds kernel cmdline words after `vbe` (e.g. `abs` for the
absolute-pointer / vmmouse path that `abs:` steps drive).
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def connect(path, tries=50):
    for _ in range(tries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("could not connect to socket " + path)


def drain(s):
    try:
        s.setblocking(False)
        while s.recv(65536):
            pass
    except BlockingIOError:
        pass
    finally:
        s.setblocking(True)


def mon_cmd(s, cmd, settle=0.25):
    s.sendall((cmd + "\n").encode())
    time.sleep(settle)
    drain(s)


def qmp_open(path):
    s = connect(path)
    time.sleep(0.2)
    drain(s)                                   # server greeting
    s.sendall(b'{"execute":"qmp_capabilities"}\n')
    time.sleep(0.2)
    drain(s)
    return s


def qmp(s, execute, arguments=None):
    obj = {"execute": execute}
    if arguments is not None:
        obj["arguments"] = arguments
    s.sendall((json.dumps(obj) + "\n").encode())
    time.sleep(0.05)
    drain(s)


def send_events(s, events):
    qmp(s, "input-send-event", {"events": events})


def mouse_move(s, dx, dy, step=16):
    """Send a relative move in small chunks so PS/2 packets don't overflow."""
    def chunks(v):
        out = []
        while abs(v) > step:
            out.append(step if v > 0 else -step)
            v -= step if v > 0 else -step
        if v:
            out.append(v)
        return out or [0]
    cx, cy = chunks(dx), chunks(dy)
    for i in range(max(len(cx), len(cy))):
        ex = cx[i] if i < len(cx) else 0
        ey = cy[i] if i < len(cy) else 0
        evs = []
        if ex:
            evs.append({"type": "rel", "data": {"axis": "x", "value": ex}})
        if ey:
            evs.append({"type": "rel", "data": {"axis": "y", "value": ey}})
        if evs:
            send_events(s, evs)
        time.sleep(0.03)


def mouse_abs(s, ax, ay):
    """Move the absolute pointer (drives an absolute device like vmmouse).
    ax/ay are in QEMU's 0..32767 axis range (0,0 = top-left)."""
    send_events(s, [
        {"type": "abs", "data": {"axis": "x", "value": int(ax)}},
        {"type": "abs", "data": {"axis": "y", "value": int(ay)}},
    ])
    time.sleep(0.05)


def mouse_btn(s, down):
    send_events(s, [{"type": "btn", "data": {"button": "left", "down": down}}])
    time.sleep(0.05)


def do_mouse(qmp_sock, script, mon_sock=None):
    for step in [s.strip() for s in script.split(";") if s.strip()]:
        if step.startswith("move:"):
            dx, dy = step[5:].split(",")
            mouse_move(qmp_sock, int(dx), int(dy))
        elif step.startswith("abs:"):
            ax, ay = step[4:].split(",")
            mouse_abs(qmp_sock, int(ax), int(ay))
        elif step == "click":
            mouse_btn(qmp_sock, True)
            mouse_btn(qmp_sock, False)
        elif step == "down":
            mouse_btn(qmp_sock, True)
        elif step == "up":
            mouse_btn(qmp_sock, False)
        elif step.startswith("wait:"):
            time.sleep(float(step[5:]))     # let a launched app settle mid-script
        elif step.startswith("key:") and mon_sock is not None:
            mon_cmd(mon_sock, "sendkey " + step[4:])   # interleave keys with clicks
        else:
            sys.stderr.write("ignoring unknown mouse step: %r\n" % step)
        time.sleep(0.1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("disk")
    ap.add_argument("out")
    ap.add_argument("--keys", default="", help="comma-separated QEMU keynames")
    ap.add_argument("--mouse", default="", help="';'-separated mouse steps")
    ap.add_argument("--append", default="", help="extra kernel cmdline words (after 'vbe')")
    ap.add_argument("--delay", type=float, default=6.0, help="boot settle seconds")
    ap.add_argument("--serial", default="", help="write the serial log here too")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="aurora-shot-")
    mon = os.path.join(tmp, "mon.sock")
    qmps = os.path.join(tmp, "qmp.sock")
    serial = args.serial or os.path.join(tmp, "serial.log")
    ppm = os.path.join(tmp, "screen.ppm")

    qemu = [
        "qemu-system-i386", "-kernel", args.kernel, "-m", "64M",
        "-drive", "file=%s,format=raw,if=ide" % args.disk,
        "-vga", "std", "-append", ("vbe " + args.append).strip(), "-display", "none",
        "-serial", "file:" + serial,
        "-monitor", "unix:%s,server,nowait" % mon,
        "-qmp", "unix:%s,server,nowait" % qmps,
        "-no-reboot", "-no-shutdown",
    ]
    proc = subprocess.Popen(qemu, stderr=subprocess.DEVNULL)
    s = None
    try:
        time.sleep(args.delay)
        s = connect(mon)
        time.sleep(0.3)
        drain(s)
        if args.mouse:                          # position/click first ...
            q = qmp_open(qmps)
            do_mouse(q, args.mouse, s)          # `key:` steps interleave via monitor
            q.close()
            time.sleep(0.4)
        if args.keys:                           # ... then type into the focused window
            for k in [k for k in args.keys.split(",") if k]:
                mon_cmd(s, "sendkey " + k)
            time.sleep(0.4)
        mon_cmd(s, "screendump " + ppm, settle=1.2)
    finally:
        try:
            if s is None:
                s = connect(mon, tries=5)
            mon_cmd(s, "quit", settle=0.2)
            s.close()
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
    if os.path.exists(serial):
        for line in open(serial):
            if any(m in line for m in ("[fb]", "[wm]", "[term]")):
                sys.stdout.write("  " + line.rstrip() + "\n")
    print("Wrote %s" % args.out)


if __name__ == "__main__":
    main()
