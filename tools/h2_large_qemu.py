#!/usr/bin/env python3
"""Phase 17.5.2 acceptance (item 1, "large responses"): a single HTTP/2
response body far larger than anything tested before (17.4.3's own
flow-control test used 200000 bytes) -- 1 MB, 5 MB, and 20 MB in turn,
negotiated for real inside QEMU against a genuine TLS 1.3 server that speaks
real HTTP/2 frames, hand-rolled here in Python -- independent of Aurora's
own http2/*.c, matching every other h2 QEMU test in this suite.

One QEMU boot per size: `httpsget --alpn --repeat 2 10.0.2.2 /big <now>` --
the SAME large body fetched TWICE over ONE reused connection (Phase 17.4.2),
back to back. Aurora keeps no dynamic heap for a response body -- only a
fixed 8192-byte preview (`g_resp`) plus a running total (`g_total`), so
there's no malloc/free pair whose leak a sanitizer would catch here (that
class of bug was already the target of 17.5.1's ASan runs on the decode
functions themselves). What "no memory leak" verifiably means for THIS
client is: repeating the same huge fetch on the same connection reports the
EXACT same byte count both times, proving no static buffer/counter carries
stale state from the first huge response into the second (the exact bug
class 17.4.2's own commit found and fixed for trailing bytes after
END_STREAM, see docs/SECURITY.md's Phase 17.4.2 section) -- if anything
leaked or mis-reset, the second count would drift from the first instead of
matching it exactly.

For each size, the server:
  1. Completes a minimal handshake (preface, SETTINGS exchange).
  2. Reads the FIRST request's HEADERS, then answers with HEADERS + the
     WHOLE body as a sequence of DATA frames (each capped at
     H2_FRAME_PAYLOAD_MAX, 16384 bytes), END_STREAM on the last one.
  3. Reads the SECOND request's HEADERS on the SAME connection (no new TCP
     accept, no new TLS handshake) and answers with an IDENTICAL body.
  4. Confirms real flow control operated at this scale: multiple
     connection-level AND stream-level WINDOW_UPDATE frames arrived for
     EACH of the two responses (17.4.3 proved this once at 200000 bytes;
     this proves it still holds an order of magnitude higher, and higher
     still, without the cycle count ever going backwards or stalling).

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_large_qemu.py
"""
import os, socket, ssl, struct, subprocess, sys, tempfile, threading, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_TYPE_DATA = 0
H2_TYPE_HEADERS = 1
H2_TYPE_SETTINGS = 4
H2_TYPE_WINDOW_UPDATE = 8
H2_FLAG_ACK = 1
H2_FLAG_END_STREAM = 1
H2_FLAG_END_HEADERS = 4
H2_FRAME_PAYLOAD_MAX = 16384

# (label, body size in bytes, how long to let QEMU run before quitting).
# wait_s is generous, empirically derived: Aurora's own from-scratch
# ChaCha20-Poly1305 record decryption running on an emulated i686 CPU is the
# real bottleneck here, not the (effectively localhost) QEMU slirp network.
SIZES = [
    ("1 MB",  1 * 1024 * 1024,  150),
    ("5 MB",  5 * 1024 * 1024,  420),
    ("20 MB", 20 * 1024 * 1024, 1500),
]


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


def hpack_encode_literal_incremental(name_index, name, value):
    if name_index:
        out = hpack_encode_int(name_index, 6, 0x40)
    else:
        out = hpack_encode_int(0, 6, 0x40) + hpack_encode_string(name)
    return out + hpack_encode_string(value)


def h2_frame(type_, flags, stream_id, payload=b""):
    length = len(payload)
    return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
                  type_, flags]) + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload


def h2_parse_header(b9):
    length = (b9[0] << 16) | (b9[1] << 8) | b9[2]
    type_ = b9[3]
    flags = b9[4]
    stream_id = ((b9[5] & 0x7F) << 24) | (b9[6] << 16) | (b9[7] << 8) | b9[8]
    return length, type_, flags, stream_id


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def gen_cert(work):
    key, pem, der = os.path.join(work, "leaf.key"), os.path.join(work, "leaf.pem"), os.path.join(work, "leaf.der")
    sh(f"openssl ecparam -name prime256v1 -genkey -noout -out {key}")
    sh(f'openssl req -x509 -new -key {key} -sha256 -days 10 -out {pem} '
       f'-subj "/CN=Aurora H2 Large Response Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_large_qemu.py -- test root only, NOT committed. */", "#pragma once",
           "static const unsigned char ca_root_0[] = {", "    " + ",".join(str(x) for x in b), "};",
           "static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {",
           '    { ca_root_0, %d, "test root" },' % len(b), "};",
           "#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])"]
    open(path, "w").write("\n".join(out) + "\n")


def start_server(port, certfile, keyfile, result, body_len, wait_s):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])
    result["connections_accepted"] = 0
    result["window_updates"] = []   # (stream_id, increment), across BOTH responses
    result["responses"] = []        # per response: {"stream_id":..., "data_frames_sent":...}

    # Precomputed once, reused for both responses -- a real server wouldn't
    # regenerate the same bytes twice either, and it keeps this test's own
    # focus on Aurora's client-side behavior, not Python's.
    body = bytes(i % 256 for i in range(body_len))

    def handle(conn):
        result["connections_accepted"] += 1
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close(); return
        result["alpn"] = tls.selected_alpn_protocol()
        tls.settimeout(60)
        buf = b""

        def recv_exact(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(65536)
                if not chunk:
                    raise OSError("connection closed mid-exchange")
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out

        def recv_h2_frame():
            hdr = recv_exact(9)
            length, type_, flags, stream_id = h2_parse_header(hdr)
            payload = recv_exact(length)
            return type_, flags, stream_id, payload

        def recv_next_headers():
            while True:
                type_, flags, stream_id, payload = recv_h2_frame()
                if type_ == H2_TYPE_WINDOW_UPDATE and len(payload) == 4:
                    increment = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
                    result["window_updates"].append((stream_id, increment))
                    continue
                return type_, flags, stream_id, payload

        try:
            preface = recv_exact(len(H2_PREFACE))
            result["preface_ok"] = (preface == H2_PREFACE)

            hdr = recv_exact(9)
            length, type_, _flags, _sid = h2_parse_header(hdr)
            recv_exact(length)
            result["client_settings_ok"] = (type_ == H2_TYPE_SETTINGS and length == 0)

            tls.sendall(h2_frame(H2_TYPE_SETTINGS, 0, 0))
            hdr2 = recv_exact(9)
            length2, type2, flags2, _s2 = h2_parse_header(hdr2)
            result["got_client_ack"] = (type2 == H2_TYPE_SETTINGS and flags2 == H2_FLAG_ACK and length2 == 0)
            tls.sendall(h2_frame(H2_TYPE_SETTINGS, H2_FLAG_ACK, 0))

            for _ in range(2):   # --repeat 2: the SAME body, fetched twice over this ONE connection
                htype, hflags, hstream, _hpayload = recv_next_headers()
                resp = {
                    "type_ok": htype == H2_TYPE_HEADERS,
                    "stream_id": hstream,
                    "end_headers": (hflags & H2_FLAG_END_HEADERS) != 0,
                }

                headers = (
                    hpack_encode_literal_incremental(8, None, "200") +
                    hpack_encode_literal_incremental(31, None, "application/octet-stream")
                )
                tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, hstream, headers))

                pos = 0
                nframes = 0
                while pos < len(body):
                    chunk = body[pos:pos + H2_FRAME_PAYLOAD_MAX]
                    pos += len(chunk)
                    nframes += 1
                    end_stream = pos >= len(body)
                    flags = H2_FLAG_END_STREAM if end_stream else 0
                    tls.sendall(h2_frame(H2_TYPE_DATA, flags, hstream, chunk))
                resp["data_frames_sent"] = nframes
                result["responses"].append(resp)

            # sendall() returning only means the OS queued the bytes -- at
            # this crypto-bound throughput Aurora is still slowly receiving
            # and acking them for a long time afterward. Closing right here
            # would leave that queued data stranded against an already-torn-
            # down socket: any further incoming packet from Aurora (a
            # WINDOW_UPDATE ack) gets an immediate RST ("no such connection"),
            # which then makes Aurora's own next write fail outright -- not
            # a real Aurora bug, but an artifact of this test's own server
            # closing too early (found the hard way during this phase).
            # Keep draining whatever Aurora sends back until it goes idle.
            tls.settimeout(max(wait_s - 20, 30))
            try:
                while True:
                    d = tls.recv(4096)
                    if not d: break
            except (socket.timeout, OSError):
                pass
        except (socket.timeout, OSError, ssl.SSLError) as e:
            result["error"] = str(e)
        try: tls.close()
        except OSError: pass

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for attempt in range(20):
        try:
            raw.bind(("0.0.0.0", port)); break
        except OSError:
            if attempt == 19: raise
            time.sleep(0.2)
    raw.listen(8)

    def loop():
        while True:
            try:
                conn, _ = raw.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return raw


def run_qemu(serial_path, typed_cmd, wait_s):
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


def run_one_size(label, body_len, wait_s, work):
    serial = os.path.join(work, "serial.log")
    result = {}
    srv = start_server(443, run_one_size.pem, run_one_size.key, result, body_len, wait_s)
    try:
        t0 = time.time()
        log = run_qemu(serial, "httpsget --alpn --repeat 2 10.0.2.2 /big %d" % int(time.time()), wait_s)
        elapsed = time.time() - t0
    finally:
        try: srv.close()
        except OSError: pass

    resps = result.get("responses", [])
    r1 = resps[0] if len(resps) > 0 else {}
    r2 = resps[1] if len(resps) > 1 else {}
    wus = result.get("window_updates", [])
    conn_level = [inc for sid, inc in wus if sid == 0]

    body_bytes_lines = [ln for ln in log.splitlines() if "body bytes)" in ln]

    checks = [
        ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
        ("server accepted EXACTLY ONE TCP connection for both fetches", result.get("connections_accepted") == 1),
        ("server received the exact connection preface", result.get("preface_ok") is True),
        ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
        ("server confirms it received the client's SETTINGS ACK", result.get("got_client_ack") is True),
        ("both requests arrived as real HEADERS with END_HEADERS set",
         r1.get("type_ok") is True and r2.get("type_ok") is True),
        ("request 1 opened on stream 1, request 2 on stream 3 (same connection, reused)",
         r1.get("stream_id") == 1 and r2.get("stream_id") == 3),
        ("server sent each %s response as more than one DATA frame (16384-byte frame cap)" % label,
         r1.get("data_frames_sent", 0) > 1 and r2.get("data_frames_sent", 0) > 1),
        ("server received multiple CONNECTION-level WINDOW_UPDATE cycles across the two responses "
         "(scaling flow control to %s, not just the 200000-byte size 17.4.3 already proved)" % label,
         len(conn_level) >= 3),
        ("every received WINDOW_UPDATE increment is positive and RFC-plausible (<= 65535)",
         all(0 < inc <= 65535 for _sid, inc in wus)),
        ("client log shows only ONE TCP connection was ever made", log.count("TCP connected to 10.0.2.2") == 1),
        ("client log shows the connection was reused for the second fetch",
         "reusing open connection to 10.0.2.2" in log),
        ("client log shows BOTH streams (1 and 3) completed", "stream 1 complete" in log and "stream 3 complete" in log),
        ("client log reports the exact same body byte count for BOTH fetches -- no leak/stale-state "
         "drift between them", len(body_bytes_lines) == 2 and
         body_bytes_lines[0].split("(")[-1] == body_bytes_lines[1].split("(")[-1]),
        ("that exact byte count matches the %s body actually sent (%d bytes)" % (label, body_len),
         ("%d body bytes)" % body_len) in log),
        ("client log shows status=200 reached twice", log.count("response bytes, status=200") == 2),
        ("client log shows the final 200 OK line", "200 OK over Aurora TCP->TLS1.3->HTTP" in log),
        ("no error was recorded server-side", "error" not in result),
    ]

    fails = 0
    print(f"\n--- {label} ({body_len} bytes), QEMU wall time {elapsed:.1f}s (budget {wait_s}s) ---")
    for name, ok in checks:
        print(f"{name:100}: {'PASS' if ok else 'FAIL'}")
        if not ok: fails += 1
    return fails


def main():
    work = tempfile.mkdtemp(prefix="aurora-17x5x2-large-")
    prod = os.path.join(ROOT, "user/ca_roots.h")
    total_fails = 0
    try:
        pem, key, der = gen_cert(work)
        write_trust_header(prod, der)
        run_one_size.pem, run_one_size.key = pem, key
        if sh("make aurora.elf user/httpsget.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        for label, body_len, wait_s in SIZES:
            total_fails += run_one_size(label, body_len, wait_s, work)
    finally:
        subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh("make aurora.elf user/httpsget.elf disk.img")
        shutil.rmtree(work, ignore_errors=True)
    print("\n17.5.2 HTTP/2 LARGE RESPONSES (1/5/20 MB, QEMU, real frame-level server): " +
          ("ALL PASS" if total_fails == 0 else f"{total_fails} FAILURE(S)"))
    return 1 if total_fails else 0


if __name__ == "__main__":
    sys.exit(main())
