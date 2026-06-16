#!/usr/bin/env python3
"""Headless check of window dragging (9.4/9.5) and the close button.

Boots the real kernel (VBE framebuffer path) twice, drives the QEMU mouse over
QMP, screendumps the live framebuffer, and asserts at the pixel level that:

  drag  -> the front Terminal's red close dot moved to the dragged-to location
  close -> clicking the red dot destroyed the window (its app logs the close)

This mirrors tools/screendump.py but adds pixel assertions so the milestone is
verifiable without a display.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

RED = (0xFF, 0x5F, 0x57)        # close-button (red traffic light)


def connect(path, tries=100):
    for _ in range(tries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("connect failed: " + path)


def qmp_open(path):
    s = connect(path)
    time.sleep(0.2)
    s.recv(65536)
    s.sendall(b'{"execute":"qmp_capabilities"}\n')
    time.sleep(0.2)
    s.recv(65536)
    return s


def qmp(s, execute, arguments=None):
    obj = {"execute": execute}
    if arguments is not None:
        obj["arguments"] = arguments
    s.sendall((json.dumps(obj) + "\n").encode())
    time.sleep(0.05)
    try:
        s.recv(65536)
    except OSError:
        pass


def move(s, dx, dy, step=16):
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
        evs = []
        if i < len(cx) and cx[i]:
            evs.append({"type": "rel", "data": {"axis": "x", "value": cx[i]}})
        if i < len(cy) and cy[i]:
            evs.append({"type": "rel", "data": {"axis": "y", "value": cy[i]}})
        if evs:
            qmp(s, "input-send-event", {"events": evs})
        time.sleep(0.03)


def btn(s, down):
    qmp(s, "input-send-event",
        {"events": [{"type": "btn", "data": {"button": "left", "down": down}}]})
    time.sleep(0.06)


def boot(tmp, tag):
    mon = os.path.join(tmp, tag + "-mon.sock")
    qmps = os.path.join(tmp, tag + "-qmp.sock")
    ser = os.path.join(tmp, tag + "-serial.log")
    qemu = [
        "qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
        "-drive", "file=disk.img,format=raw,if=ide",
        "-vga", "std", "-append", "vbe", "-display", "none",
        "-serial", "file:" + ser,
        "-monitor", "unix:%s,server,nowait" % mon,
        "-qmp", "unix:%s,server,nowait" % qmps,
        "-no-reboot", "-no-shutdown",
    ]
    proc = subprocess.Popen(qemu, stderr=subprocess.DEVNULL)
    return proc, mon, qmps, ser


def load_ppm(path):
    with open(path, "rb") as f:
        assert f.readline().strip() == b"P6"
        w, h = map(int, f.readline().split())
        f.readline()
        data = f.read()
    return w, h, data


def near(data, w, x, y, rgb, tol=24, rad=4):
    for dy in range(-rad, rad + 1):
        for dx in range(-rad, rad + 1):
            i = ((y + dy) * w + (x + dx)) * 3
            if 0 <= i < len(data) - 2:
                if (abs(data[i] - rgb[0]) <= tol and
                        abs(data[i + 1] - rgb[1]) <= tol and
                        abs(data[i + 2] - rgb[2]) <= tol):
                    return True
    return False


def scenario_drag(tmp):
    proc, mon, qmps, ser = boot(tmp, "drag")
    ppm = os.path.join(tmp, "drag.ppm")
    try:
        time.sleep(6)
        q = qmp_open(qmps)
        move(q, -188, 40)       # cursor center(512,384) -> t2 title bar(700,344)
        btn(q, True)
        move(q, 250, -150)      # drag window 2 by (-250,+150)
        btn(q, False)
        q.close()
        time.sleep(1.5)
        m = connect(mon)
        m.sendall(("screendump " + ppm + "\n").encode())
        time.sleep(1.2)
        m.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    w, h, data = load_ppm(ppm)
    moved = near(data, w, 236, 494, RED)        # t2 close dot at dragged-to spot
    stale = near(data, w, 486, 344, RED)        # original front-window close spot
    print("  drag: close-dot at moved (236,494):", moved)
    print("  drag: red still at original (486,344):", stale)
    return moved and not stale


def scenario_close(tmp):
    proc, mon, qmps, ser = boot(tmp, "close")
    ppm = os.path.join(tmp, "close.ppm")
    try:
        time.sleep(6)
        q = qmp_open(qmps)
        move(q, 26, 40)         # cursor center -> t2 close button (486,344)
        btn(q, True)
        btn(q, False)
        q.close()
        time.sleep(1.5)
        m = connect(mon)
        m.sendall(("screendump " + ppm + "\n").encode())
        time.sleep(1.2)
        m.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    w, h, data = load_ppm(ppm)
    log = open(ser, errors="replace").read()
    # The closed Terminal logs "[term] window N closed"; the exact id depends on
    # how many windows exist first (the Dock is window 1), so match generically.
    closed_log = "closed" in log
    t1_alive = near(data, w, 216, 164, RED)     # t1 close dot still present
    gone = not near(data, w, 486, 344, RED)     # t2 close dot no longer there
    print("  close: serial '[term] window closed':", closed_log)
    print("  close: t1 close dot still at (216,164):", t1_alive)
    print("  close: t2 close dot gone at (486,344):", gone)
    return closed_log and t1_alive and gone


def main():
    tmp = tempfile.mkdtemp(prefix="aurora-drag-")
    print("== drag ==")
    d = scenario_drag(tmp)
    print("== close ==")
    c = scenario_close(tmp)
    print("\nDRAG :", "PASS" if d else "FAIL")
    print("CLOSE:", "PASS" if c else "FAIL")
    sys.exit(0 if (d and c) else 1)


if __name__ == "__main__":
    main()
