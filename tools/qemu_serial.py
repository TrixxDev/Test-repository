"""Phase 18.0: shared QEMU launch helper using the serial command channel.

Every earlier h2_*_qemu.py test typed its command by scancode-injecting one
key at a time through the QEMU monitor's `sendkey` (drivers/keyboard.c),
sleeping ~0.12s per character, and juggling a shift-key map for uppercase
and punctuation. That was slow (seconds per test just to "type"), and fragile
for any character not in the small km/isupper() map in each script's own
key_for() helper.

Since Phase 18.0, drivers/serial.c also receives bytes (IRQ4) and
drivers/console.c merges them into the same input stream as the keyboard, so
a shell run under QEMU can be driven by writing raw ASCII straight to COM1 --
no scancodes, no shift map, no per-character delay. This module gives QEMU's
COM1 a chardev backed by a UNIX socket instead of a plain file: the same
socket is used to both send typed input and read back everything the kernel
would otherwise have only written to -serial file:PATH (boot log, the
console's local echo of what was "typed", and normal program output) -- so
existing checks that grep the returned text for things like "200 OK" or
"stream 3 complete" need no changes at all.
"""
import os, socket, subprocess, tempfile, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_NET_ARGS = ("-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0")


def run_qemu_serial(typed_cmd, wait_s=35, boot_wait=7, extra_qemu_args=DEFAULT_NET_ARGS):
    """Boot QEMU, wait `boot_wait`s for the boot log to settle, send
    `typed_cmd` + Enter over COM1, wait up to `wait_s`s collecting output,
    then shut QEMU down and return everything captured as one string.
    """
    tmp = tempfile.mkdtemp()
    sock_path = os.path.join(tmp, "com1.sock")
    q = ["qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
         "-drive", "file=disk.img,format=raw,if=ide", "-display", "none",
         "-chardev", "socket,id=com1,path=%s,server=on,wait=off" % sock_path,
         "-serial", "chardev:com1",
         "-no-reboot", "-no-shutdown"] + list(extra_qemu_args)
    p = subprocess.Popen(q, cwd=ROOT, stderr=subprocess.DEVNULL)
    buf = b""
    try:
        s = None
        for _ in range(100):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock_path)
                break
            except OSError:
                time.sleep(0.1)
        if s is None:
            raise RuntimeError("QEMU never opened its serial chardev socket")
        time.sleep(boot_wait)
        s.sendall(typed_cmd.encode() + b"\n")
        s.settimeout(0.5)
        deadline = time.time() + wait_s
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
        s.close()
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    return buf.decode(errors="replace")
