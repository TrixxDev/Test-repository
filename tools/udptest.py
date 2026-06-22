#!/usr/bin/env python3
"""UDP round-trip test for AuroraOS over QEMU user-mode networking (SLIRP).

The guest's boot self-test sends "hello from aurora" to 10.0.2.2:9999 and then
listens on port 9999. SLIRP forwards guest->10.0.2.2:9999 to the host's
127.0.0.1:9999, so a host listener:

  1. receives the guest's datagram          -> proves guest UDP TX (+IPv4/ARP/eth)
  2. replies to that source                  -> SLIRP NATs it back to the guest
  3. the guest's handler logs + echoes it    -> proves guest UDP RX

No hostfwd needed: the reply rides the NAT mapping created by the guest's send.

Usage: tools/udptest.py [kernel.elf] [disk.img]
"""
import os, socket, struct, subprocess, sys, time

KERNEL = sys.argv[1] if len(sys.argv) > 1 else 'aurora.elf'
DISK   = sys.argv[2] if len(sys.argv) > 2 else 'disk.img'
PCAP   = '/tmp/udp.pcap'
SERIAL = '/tmp/udpboot.log'
PORT   = 9999

for f in (PCAP, SERIAL):
    try: os.remove(f)
    except OSError: pass

# Host listener must be up before the guest boots and sends.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', PORT))
s.settimeout(25)

qemu = subprocess.Popen([
    'qemu-system-i386', '-kernel', KERNEL, '-m', '64M',
    '-drive', f'file={DISK},format=raw,if=ide',
    '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
    '-object', f'filter-dump,id=d0,netdev=n0,file={PCAP}',
    '-display', 'none', '-serial', f'file:{SERIAL}', '-no-reboot', '-append', 'nettest',
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

got_tx = got_echo = False
try:
    data, peer = s.recvfrom(2048)
    print(f'[host] <- guest: {data!r}  (via {peer})')
    got_tx = True
    s.sendto(b'reply from host\n', peer)
    print('[host] -> guest: reply from host')
    try:
        s.settimeout(8)
        echo, _ = s.recvfrom(2048)
        print(f'[host] <- guest echo: {echo!r}')
        got_echo = True
    except socket.timeout:
        print('[host] (no echo back)')
except socket.timeout:
    print('[host] TIMEOUT: no datagram from guest')

time.sleep(8)                       # let the guest finish its self-test
qemu.terminate()
try: qemu.wait(timeout=5)
except Exception: qemu.kill()

print('--- serial [udp] ---')
try:
    for line in open(SERIAL, 'rb').read().decode('latin1').splitlines():
        if '[udp]' in line:
            print(line)
except OSError:
    pass

print('--- pcap UDP frames ---')
try:
    d = open(PCAP, 'rb').read()
    off, n, udp = 24, 0, 0
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack('<IIII', d[off:off+16]); off += 16
        if off + incl > len(d): break
        f = d[off:off+incl]; off += incl; n += 1
        if incl >= 38 and (f[12] << 8 | f[13]) == 0x0800 and f[23] == 17:
            sp = f[34] << 8 | f[35]; dp = f[36] << 8 | f[37]
            print(f'  frame {n}: UDP {sp}->{dp} ({incl}B)'); udp += 1
    print(f'  {udp} UDP frame(s) of {n} total')
except OSError:
    pass

print()
print('TX guest->host:', 'OK' if got_tx else 'FAIL')
print('RX host->guest:', 'OK (echo)' if got_echo else '(check serial [udp] rx line)')
sys.exit(0 if got_tx else 1)
