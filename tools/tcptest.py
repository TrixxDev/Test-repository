#!/usr/bin/env python3
"""TCP handshake test for AuroraOS over QEMU user-mode networking (SLIRP).

The guest's boot self-test does tcp_connect(10.0.2.2:80). SLIRP forwards guest
connections to 10.0.2.2 to the host's 127.0.0.1, so a host TCP listener on :80
completes the three-way handshake (the host kernel answers SYN with SYN-ACK; the
guest replies ACK and reaches ESTABLISHED).

Proves Phase 1: SYN / SYN-ACK / ACK -> ESTABLISHED. No data is exchanged.

Usage: tools/tcptest.py [kernel.elf] [disk.img] [port]
"""
import os, socket, struct, subprocess, sys, time

KERNEL = sys.argv[1] if len(sys.argv) > 1 else 'aurora.elf'
DISK   = sys.argv[2] if len(sys.argv) > 2 else 'disk.img'
PORT   = int(sys.argv[3]) if len(sys.argv) > 3 else 80
PCAP   = '/tmp/tcp.pcap'
SERIAL = '/tmp/tcpboot.log'

for f in (PCAP, SERIAL):
    try: os.remove(f)
    except OSError: pass

# Listener must be up before the guest boots and connects.
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

accepted = False
try:
    conn, peer = srv.accept()
    print(f'[host] accepted TCP connection from {peer}  -> handshake completed')
    accepted = True
    conn.close()
except socket.timeout:
    print('[host] TIMEOUT: no inbound TCP connection from guest')

time.sleep(6)                       # let the guest log its final state
qemu.terminate()
try: qemu.wait(timeout=5)
except Exception: qemu.kill()

print('--- serial [tcp] ---')
try:
    for line in open(SERIAL, 'rb').read().decode('latin1').splitlines():
        if '[tcp]' in line:
            print(line)
except OSError:
    pass

print('--- pcap TCP segments (flags) ---')
def tcpflags(b):
    names = [(0x02,'SYN'),(0x10,'ACK'),(0x01,'FIN'),(0x04,'RST'),(0x08,'PSH')]
    return '|'.join(n for m, n in names if b & m) or '-'
try:
    d = open(PCAP, 'rb').read()
    off, n, t = 24, 0, 0
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack('<IIII', d[off:off+16]); off += 16
        if off + incl > len(d): break
        f = d[off:off+incl]; off += incl; n += 1
        if incl >= 54 and (f[12] << 8 | f[13]) == 0x0800 and f[23] == 6:
            ihl = (f[14] & 0x0f) * 4
            tcp = 14 + ihl
            sp = f[tcp] << 8 | f[tcp+1]; dp = f[tcp+2] << 8 | f[tcp+3]
            fl = f[tcp+13]
            print(f'  frame {n}: TCP {sp}->{dp} [{tcpflags(fl)}]'); t += 1
    print(f'  {t} TCP segment(s) of {n} total')
except OSError:
    pass

print()
print('Handshake:', 'OK (ESTABLISHED)' if accepted else 'FAIL')
sys.exit(0 if accepted else 1)
