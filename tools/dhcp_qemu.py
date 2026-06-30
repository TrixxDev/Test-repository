#!/usr/bin/env python3
"""Phase 15.3 acceptance: a real DHCP lease, negotiated inside QEMU against
SLIRP's built-in DHCP server, end to end -- DISCOVER -> OFFER -> REQUEST -> ACK
-- with the leased config actually usable by the rest of the stack (ARP/ICMP),
not just printed.

Three scenarios:
  1. default SLIRP subnet (10.0.2.0/24) -- the DHCP-leased config must come out
     byte-identical to the static defaults net/netcfg.c falls back to, proving
     Phase 15.3 is a drop-in (no other phase's behavior changes).
  2. a DIFFERENT subnet (`-netdev user,...,net=...`) -- proves Aurora adapts to
     whatever the network actually hands out, not just "coincidentally already
     matching" the hardcoded defaults. `nettest` is also passed so the boot
     pings the (dynamically learned) gateway, proving the leased IP/mask/
     gateway are not just parsed correctly but actually wired into ARP/IPv4 and
     usable for real traffic.
  3. `nodhcp` on the cmdline -- the escape hatch must skip DHCP entirely and
     leave the static defaults in place.

Self-contained and reproducible: no host-side DHCP server needed (SLIRP brings
its own), no files written to the repo. Requires: qemu-system-i386, the cross
toolchain (i.e. `make`). Run from the repo root: python3 tools/dhcp_qemu.py
"""
import os, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def run_qemu(serial_path, netdev_extra="", cmdline=""):
    """Boot Aurora text-mode (no disk needed -- embedded init), capture serial."""
    if os.path.exists(serial_path): os.remove(serial_path)
    q = ["qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
         "-display", "none", "-serial", "file:" + serial_path,
         "-netdev", "user,id=n0" + (("," + netdev_extra) if netdev_extra else ""),
         "-device", "virtio-net-pci,netdev=n0",
         "-no-reboot", "-no-shutdown"]
    if cmdline:
        q += ["-append", cmdline]
    p = subprocess.Popen(q, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(10)
    finally:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-15x3-")
    serial = os.path.join(work, "serial.log")
    fails = 0
    try:
        if sh("make aurora.elf").returncode != 0:
            print("build FAILED"); return 1

        # (1) default subnet: DHCP-leased config must match the static fallback.
        log = run_qemu(serial)
        ok = "[dhcp] DISCOVER" in log and \
             "[dhcp] OFFER 10.0.2.15 from server 10.0.2.2" in log and \
             "[dhcp] ACK: bound 10.0.2.15 mask 255.255.255.0 gw 10.0.2.2 dns 10.0.2.3" in log
        line = next((l for l in log.splitlines() if l.startswith("[dhcp] ACK")), "(no ACK)")
        print(f"{'default subnet (drop-in)':28}: {'PASS' if ok else 'FAIL'}  {line.strip()}")
        if not ok: fails += 1

        # (2) a different subnet: must adapt, and the leased config must be
        # ARP/ICMP-usable (nettest pings the gateway right after DHCP).
        log = run_qemu(serial, netdev_extra="net=192.168.77.0/24,dhcpstart=192.168.77.15",
                       cmdline="nettest")
        bound_ok = "[dhcp] ACK: bound 192.168.77.15 mask 255.255.255.0 gw 192.168.77.2 dns 192.168.77.3" in log
        ping_ok  = "[icmp] PING 192.168.77.2" in log and "[icmp] 4/4 replies received -- PING OK" in log
        ok = bound_ok and ping_ok
        line = next((l for l in log.splitlines() if l.startswith("[dhcp] ACK")), "(no ACK)")
        print(f"{'different subnet (adapts)':28}: {'PASS' if ok else 'FAIL'}  {line.strip()}"
              f"{'' if ping_ok else '  [gateway ping did not confirm]'}")
        if not ok: fails += 1

        # (3) nodhcp: the escape hatch must skip DHCP outright.
        log = run_qemu(serial, cmdline="nodhcp")
        ok = "[dhcp] DISCOVER" not in log and "[dhcp] skipped (nodhcp)" in log
        line = next((l for l in log.splitlines() if "dhcp" in l), "(no dhcp line)")
        print(f"{'nodhcp escape hatch':28}: {'PASS' if ok else 'FAIL'}  {line.strip()}")
        if not ok: fails += 1
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    print("\n15.3 DHCP (QEMU, real SLIRP server): " + ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
