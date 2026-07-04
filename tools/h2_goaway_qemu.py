#!/usr/bin/env python3
"""Phase 17.5.2 acceptance (item 5, "negative tests"): GOAWAY arriving at
an unexpected moment, negotiated for real inside QEMU against a genuine
TLS 1.3 server that speaks real HTTP/2 frames, hand-rolled here in Python
-- independent of Aurora's own http2/*.c, matching every other h2 QEMU
test in this suite.

user/httpsget.c has TWO separate places that recognize GOAWAY, each
watching for it among whatever OTHER frame types it's currently waiting
for -- h2_handshake()'s own SETTINGS/ACK wait loop, and h2_fetch()'s own
response-reading loop. Both already print a diagnostic and return -1
(never silently hang, never crash) per code inspection -- this test
verifies that against a REAL server, the same discipline this whole
project applies everywhere else ("never trust client-side logs alone",
see e.g. h2_reuse_qemu.py's own header comment): a fuzzer calling these
functions in isolation (17.5.1's h2_fuzz.c) doesn't simulate a live,
multi-frame protocol EXCHANGE the way a real, if adversarial, server does.

Two independent QEMU boots, each its own `httpsget --alpn 10.0.2.2 /x <now>`:

  1. GOAWAY during the handshake -- the server never sends its own
     SETTINGS at all; a GOAWAY arrives instead, immediately after the
     client's preface+SETTINGS. Exercises h2_handshake()'s own check
     (line ~1184 in user/httpsget.c at the time of writing).
  2. GOAWAY mid-response -- the server completes a normal handshake,
     receives the request, sends response HEADERS plus ONE (deliberately
     incomplete, no END_STREAM) DATA frame, then sends GOAWAY instead of
     ever finishing the response. Exercises h2_fetch()'s own check.

In both cases: Aurora's shell prints "[exit N]" after every foreign
command completes (already relied on elsewhere in this project's own
debugging) -- a nonzero exit here, reached promptly rather than after the
test's own wait_s budget is exhausted, is direct proof httpsget aborted
cleanly rather than hanging.

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_goaway_qemu.py
"""
import os, re, socket, ssl, struct, subprocess, sys, tempfile, threading, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_TYPE_DATA = 0
H2_TYPE_HEADERS = 1
H2_TYPE_SETTINGS = 4
H2_TYPE_GOAWAY = 0x7
H2_FLAG_ACK = 1
H2_FLAG_END_STREAM = 1
H2_FLAG_END_HEADERS = 4


def hpack_encode_int(value, prefix_bits, flag_bits=0):
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([flag_bits | value])
    out = bytearray([flag_bits | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value % 128) | 0x80)
        value //= 128
    out.append(value)
    return bytes(out)


def hpack_encode_string(s):
    b = s.encode("latin1")
    return hpack_encode_int(len(b), 7, 0x00) + b


def hpack_encode_indexed(index):
    return hpack_encode_int(index, 7, 0x80)


def hpack_encode_literal_without_indexing(name_index, name, value):
    if name_index:
        out = hpack_encode_int(name_index, 4, 0x00)
    else:
        out = hpack_encode_int(0, 4, 0x00) + hpack_encode_string(name)
    return out + hpack_encode_string(value)


def h2_frame(type_, flags, stream_id, payload=b""):
    length = len(payload)
    return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
                  type_, flags]) + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload


def h2_goaway(last_stream_id, error_code, debug=b""):
    return struct.pack(">II", last_stream_id & 0x7FFFFFFF, error_code) + debug


def h2_parse_header(b9):
    length = (b9[0] << 16) | (b9[1] << 8) | b9[2]
    type_ = b9[3]
    flags = b9[4]
    stream_id = ((b9[5] & 0x7F) << 24) | (b9[6] << 16) | (b9[7] << 8) | b9[8]
    return length, type_, flags, stream_id


def start_listener(port, handle):
    """Bind :port and accept connections into `handle` on daemon threads,
    with a real, joinable shutdown -- this script runs TWO scenarios in
    one process, both binding the SAME port (httpsget always targets 443)
    in turn, so the first listener's accept-loop thread must have
    genuinely exited (not just had its socket closed out from under a
    blocking accept() call, which isn't guaranteed to unblock promptly on
    every platform) before the second scenario tries to bind. A short
    accept() timeout plus an Event the loop actually checks makes shutdown
    deterministic instead of racing the OS to release the port."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for attempt in range(50):
        try: raw.bind(("0.0.0.0", port)); break
        except OSError:
            if attempt == 49: raise
            time.sleep(0.2)
    raw.listen(8)
    raw.settimeout(0.5)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = raw.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return raw, stop, t


def stop_listener(raw, stop, t):
    stop.set()
    t.join(timeout=5)
    try: raw.close()
    except OSError: pass


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def gen_cert(work):
    key, pem, der = os.path.join(work, "leaf.key"), os.path.join(work, "leaf.pem"), os.path.join(work, "leaf.der")
    sh(f"openssl ecparam -name prime256v1 -genkey -noout -out {key}")
    sh(f'openssl req -x509 -new -key {key} -sha256 -days 10 -out {pem} '
       f'-subj "/CN=Aurora H2 GOAWAY Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_goaway_qemu.py -- test root only, NOT committed. */", "#pragma once",
           "static const unsigned char ca_root_0[] = {", "    " + ",".join(str(x) for x in b), "};",
           "static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {",
           '    { ca_root_0, %d, "test root" },' % len(b), "};",
           "#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])"]
    open(path, "w").write("\n".join(out) + "\n")


def start_server_handshake_goaway(port, certfile, keyfile, result):
    """Scenario 1: GOAWAY instead of the server's own SETTINGS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])

    def handle(conn):
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close(); return
        result["alpn"] = tls.selected_alpn_protocol()
        tls.settimeout(15)
        buf = b""

        def recv_exact(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(65536)
                if not chunk: raise OSError("closed")
                buf += chunk
            out, buf2 = buf[:n], buf[n:]
            buf = buf2
            return out

        try:
            preface = recv_exact(len(H2_PREFACE))
            result["preface_ok"] = (preface == H2_PREFACE)
            hdr = recv_exact(9)
            length, type_, _f, _s = h2_parse_header(hdr)
            recv_exact(length)
            result["client_settings_ok"] = (type_ == H2_TYPE_SETTINGS and length == 0)

            # No server SETTINGS at all -- GOAWAY arrives in its place.
            tls.sendall(h2_frame(H2_TYPE_GOAWAY, 0, 0, h2_goaway(0, 0, b"refusing on purpose")))
            result["goaway_sent"] = True
        except (socket.timeout, OSError, ssl.SSLError) as e:
            result["error"] = str(e)
        try: tls.close()
        except OSError: pass

    return start_listener(port, handle)


def start_server_midresponse_goaway(port, certfile, keyfile, result):
    """Scenario 2: a normal handshake and request, an incomplete response,
    then GOAWAY instead of ever finishing it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])

    def handle(conn):
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close(); return
        result["alpn"] = tls.selected_alpn_protocol()
        tls.settimeout(15)
        buf = b""

        def recv_exact(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(65536)
                if not chunk: raise OSError("closed")
                buf += chunk
            out, buf2 = buf[:n], buf[n:]
            buf = buf2
            return out

        def recv_h2_frame():
            hdr = recv_exact(9)
            length, type_, flags, stream_id = h2_parse_header(hdr)
            return type_, flags, stream_id, recv_exact(length)

        try:
            preface = recv_exact(len(H2_PREFACE))
            result["preface_ok"] = (preface == H2_PREFACE)
            hdr = recv_exact(9)
            length, type_, _f, _s = h2_parse_header(hdr)
            recv_exact(length)
            result["client_settings_ok"] = (type_ == H2_TYPE_SETTINGS and length == 0)

            tls.sendall(h2_frame(H2_TYPE_SETTINGS, 0, 0))
            hdr2 = recv_exact(9)
            length2, type2, flags2, _s2 = h2_parse_header(hdr2)
            result["got_client_ack"] = (type2 == H2_TYPE_SETTINGS and flags2 == H2_FLAG_ACK)
            tls.sendall(h2_frame(H2_TYPE_SETTINGS, H2_FLAG_ACK, 0))

            htype, hflags, hstream, _p = recv_h2_frame()
            result["request_ok"] = (htype == H2_TYPE_HEADERS and hstream == 1 and
                                    (hflags & H2_FLAG_END_HEADERS) != 0)

            headers = (
                hpack_encode_indexed(8) +
                hpack_encode_literal_without_indexing(31, None, "text/plain")
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1, headers))
            # Deliberately incomplete: no END_STREAM, response never finishes.
            tls.sendall(h2_frame(H2_TYPE_DATA, 0, 1, b"partial response, then we bail out"))
            tls.sendall(h2_frame(H2_TYPE_GOAWAY, 0, 0, h2_goaway(1, 2, b"internal error mid-response")))
            result["goaway_sent"] = True
        except (socket.timeout, OSError, ssl.SSLError) as e:
            result["error"] = str(e)
        try: tls.close()
        except OSError: pass

    return start_listener(port, handle)


def run_qemu(serial_path, typed_cmd, wait_s=30):
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
            try: s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(mon); break
            except OSError: time.sleep(0.1)
        time.sleep(7)
        km = {" ": "spc", ".": "dot", "/": "slash", "-": "minus"}
        def key_for(ch):
            if ch in km: return km[ch]
            if ch.isupper(): return "shift-" + ch.lower()
            return ch
        for ch in typed_cmd:
            s.sendall(("sendkey " + key_for(ch) + "\n").encode()); time.sleep(0.12)
        s.sendall(b"sendkey ret\n"); time.sleep(wait_s)
        s.sendall(b"quit\n"); time.sleep(0.3); s.close()
    finally:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def run_scenario(label, start_server_fn, expected_diag, work):
    result = {}
    raw, stop, thread = start_server_fn(443, run_scenario.pem, run_scenario.key, result)
    try:
        log = run_qemu(os.path.join(work, "serial.log"),
                       "httpsget --alpn 10.0.2.2 /x %d" % int(time.time()))
    finally:
        stop_listener(raw, stop, thread)

    m = re.search(r"\[exit (-?\d+)\]", log)
    exit_code = int(m.group(1)) if m else None

    checks = [
        ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
        ("server received the exact connection preface", result.get("preface_ok") is True),
        ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
        ("server sent its GOAWAY", result.get("goaway_sent") is True),
        ("client log shows the expected GOAWAY diagnostic", expected_diag in log),
        ("httpsget exited with a nonzero status (a clean, deliberate failure)",
         exit_code is not None and exit_code != 0),
        ("no hang: the shell's own \"[exit N]\" line appeared well within the wait budget "
         "(proves httpsget returned promptly, not just that QEMU eventually timed out)",
         m is not None),
        ("no crash: no fault/panic text in the log", "panic" not in log.lower() and "fault" not in log.lower()),
    ]

    fails = 0
    print(f"\n--- {label} ---")
    for name, ok in checks:
        print(f"{name:100}: {'PASS' if ok else 'FAIL'}")
        if not ok: fails += 1
    if exit_code is None:
        print("  (no '[exit N]' line found in the log at all -- see raw log tail below)")
        print("  ".join(log.splitlines()[-15:]))
    return fails


def main():
    work = tempfile.mkdtemp(prefix="aurora-17x5x2-goaway-")
    prod = os.path.join(ROOT, "user/ca_roots.h")
    total_fails = 0
    try:
        pem, key, der = gen_cert(work)
        write_trust_header(prod, der)
        run_scenario.pem, run_scenario.key = pem, key
        if sh("make user/httpsget.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        total_fails += run_scenario("GOAWAY during the handshake (instead of server SETTINGS)",
                                    start_server_handshake_goaway,
                                    "server sent GOAWAY -- refusing this connection", work)
        total_fails += run_scenario("GOAWAY mid-response (after HEADERS + partial DATA, no END_STREAM)",
                                    start_server_midresponse_goaway,
                                    "server sent GOAWAY while reading the response", work)
    finally:
        subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh("make user/httpsget.elf disk.img")
        shutil.rmtree(work, ignore_errors=True)
    print("\n17.5.2 GOAWAY AT AN UNEXPECTED MOMENT (QEMU, real frame-level server): " +
          ("ALL PASS" if total_fails == 0 else f"{total_fails} FAILURE(S)"))
    return 1 if total_fails else 0


if __name__ == "__main__":
    sys.exit(main())
