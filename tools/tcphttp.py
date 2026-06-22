#!/usr/bin/env python3
"""TCP data / HTTP test for AuroraOS over QEMU user-mode networking (SLIRP).

The guest's boot self-test connects to 10.0.2.2:80 and sends an HTTP GET. SLIRP
forwards it to the host's 127.0.0.1:80, where this minimal HTTP server:

  1. prints the request it received   -> proves guest TCP data TX (seq/ack/csum)
  2. replies "HTTP/1.0 200 OK ..."    -> proves guest TCP data RX

Usage: tools/tcphttp.py [kernel.elf] [disk.img] [port]
"""
import os, socket, struct, subprocess, sys, time

KERNEL = sys.argv[1] if len(sys.argv) > 1 else 'aurora.elf'
DISK   = sys.argv[2] if len(sys.argv) > 2 else 'disk.img'
PORT   = int(sys.argv[3]) if len(sys.argv) > 3 else 80
PCAP   = '/tmp/http.pcap'
SERIAL = '/tmp/httpboot.log'

for f in (PCAP, SERIAL):
    try: os.remove(f)
    except OSError: pass

BODY = b"Hello from the host HTTP server\n"
RESP = (b"HTTP/1.0 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: %d\r\n"
        b"Connection: close\r\n\r\n" % len(BODY)) + BODY

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('', PORT))
srv.listen(4)
srv.settimeout(30)

qemu = subprocess.Popen([
    'qemu-system-i386', '-kernel', KERNEL, '-m', '64M',
    '-drive', f'file={DISK},format=raw,if=ide',
    '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
    '-object', f'filter-dump,id=d0,netdev=n0,file={PCAP}',
    '-display', 'none', '-serial', f'file:{SERIAL}', '-no-reboot', '-append', 'nettest',
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

served = False
try:
    conn, peer = srv.accept()
    conn.settimeout(5)
    req = b''
    try:
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(1024)
            if not chunk: break
            req += chunk
    except socket.timeout:
        pass
    print(f'[host] connection from {peer}; request received:')
    for line in req.decode('latin1').splitlines():
        if line: print('   |', line)
    conn.sendall(RESP)
    print(f'[host] sent {len(RESP)}-byte HTTP/1.0 200 response')
    served = bool(req)
    conn.close()
except socket.timeout:
    print('[host] TIMEOUT: no TCP connection from guest')

time.sleep(8)
qemu.terminate()
try: qemu.wait(timeout=5)
except Exception: qemu.kill()

print('--- serial [tcp]/[http] ---')
try:
    for line in open(SERIAL, 'rb').read().decode('latin1').splitlines():
        if '[tcp]' in line or '[http]' in line:
            print(line)
except OSError:
    pass

print('--- pcap TCP segments ---')
def flags(b):
    return '|'.join(n for m, n in [(0x02,'SYN'),(0x10,'ACK'),(0x08,'PSH'),
                                   (0x01,'FIN'),(0x04,'RST')] if b & m) or '-'
try:
    d = open(PCAP, 'rb').read()
    off, n, t = 24, 0, 0
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack('<IIII', d[off:off+16]); off += 16
        if off + incl > len(d): break
        f = d[off:off+incl]; off += incl; n += 1
        if incl >= 54 and (f[12] << 8 | f[13]) == 0x0800 and f[23] == 6:
            ihl = (f[14] & 0x0f) * 4; tcp = 14 + ihl
            sp = f[tcp] << 8 | f[tcp+1]; dp = f[tcp+2] << 8 | f[tcp+3]
            dataoff = (f[tcp+12] >> 4) * 4
            plen = incl - tcp - dataoff
            print(f'  frame {n}: TCP {sp}->{dp} [{flags(f[tcp+13])}] payload={plen}B'); t += 1
    print(f'  {t} TCP segment(s) of {n} total')
except OSError:
    pass

print()
print('TCP data round-trip:', 'OK' if served else 'FAIL')
sys.exit(0 if served else 1)
