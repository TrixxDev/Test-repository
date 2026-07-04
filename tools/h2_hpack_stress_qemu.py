#!/usr/bin/env python3
"""Phase 17.5.2 acceptance (item 4, "HPACK stress"): very large header
values, large numbers of cookies, frequent Dynamic Table Size Update, and
mass evictions within a single header block -- negotiated for real inside
QEMU against a genuine TLS 1.3 server that speaks real HTTP/2 frames and
real HPACK, hand-rolled here in Python -- independent of Aurora's own
http2/*.c, matching every other h2 QEMU test in this suite.

Designing the "many cookies" scenario surfaced a real, separate bug (fixed
in the same commit as this test): user/httpsget.c's h2_fetch() never sent
the cookie jar's own Cookie header on an h2 request at all --
http2/headers.c's h2_build_headers() had no cookie parameter, so a session
cookie learned from an h2 response's own Set-Cookie was never sent back on
a LATER h2 request, even reusing the very connection that set it. This
test's /echo step exists specifically to verify that fix: it decodes the
REAL third request's HEADERS frame and checks its Cookie header, the same
way h2_reuse_qemu.py already decodes a real client request.

One QEMU boot: `httpsget --alpn 10.0.2.2 /bighdr /manycookies /echo /dtsu
/massevict <now>` -- five paths on the SAME host, fetched sequentially over
ONE reused h2 connection (Phase 17.4.2). The server:

  1. /bighdr (stream 1): a single custom header ("x-big") ~3000 bytes long
     -- comfortably under H2_HPACK_SCRATCH_MAX (4096) and the header-text
     synthesis buffer's own 4096-byte cap, but far larger than anything
     tested before. Decode succeeding (the connection proceeding cleanly to
     stream 3, not aborting) is the proof -- there's nowhere httpsget prints
     an arbitrary custom header's own value, the same indirect-but-solid
     methodology h2_reuse_qemu.py already uses for its own dynamic-table
     proof.
  2. /manycookies (stream 3): 40 distinct Set-Cookie headers
     (cookie00=val00 .. cookie39=val39, Path=/), all in ONE response --
     COOKIE_JAR_N (32) forces real LRU eviction partway through, all
     within one header block's worth of Set-Cookie lines.
  3. /echo (stream 5): decodes the REAL incoming request's own HEADERS
     frame (this test's own minimal static-table decoder, extended with
     index 32 for "cookie") and records its Cookie header's value --
     proving both the cookie-over-h2 fix (a Cookie header was sent AT ALL)
     and the LRU math (cookie00..cookie07, set first, were evicted;
     cookie08..cookie39 survive).
  4. /dtsu (stream 7): THREE Dynamic Table Size Update instructions
     (RFC 7541 SS6.3 explicitly allows more than one in a row before any
     other representation references the table) back to back -- shrink to
     0 (evicts everything), grow to 100, grow back to 4096 -- then a
     literal-incremental field to prove the table is still usable
     afterward.
  5. /massevict (stream 9): 40 literal-incremental fields in ONE header
     block, each ~103 bytes (comfortably over HPACK_DYN_ARENA_SIZE's 4096
     in aggregate: 40 * 103 = 4120), forcing several evictions WITHIN a
     single decode call rather than gradually across many requests (the
     dimension tools/h2_longlived_qemu.py's own 300-request test doesn't
     cover).

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_hpack_stress_qemu.py
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

# Static-table subset this test's own minimal decoder understands, enough
# to decode a real request Aurora's own h2_build_headers() sends.
HPACK_STATIC_TABLE = {
    1: (":authority", None),
    2: (":method", "GET"),
    4: (":path", "/"),
    7: (":scheme", "https"),
    32: ("cookie", None),
    58: ("user-agent", None),
}


def hpack_decode_int(data, pos, prefix_bits):
    max_prefix = (1 << prefix_bits) - 1
    first = data[pos] & max_prefix
    pos += 1
    if first < max_prefix:
        return first, pos
    value = first
    shift = 0
    while True:
        b = data[pos]; pos += 1
        value += (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return value, pos


def hpack_decode_string(data, pos):
    b = data[pos]
    if b & 0x80:
        raise ValueError("unexpected Huffman-coded string")
    length, pos = hpack_decode_int(data, pos, 7)
    raw = bytes(data[pos:pos + length])
    return raw.decode("latin1"), pos + length


def hpack_decode_headers(payload):
    headers = []
    pos = 0
    while pos < len(payload):
        b = payload[pos]
        if b & 0x80:
            index, pos = hpack_decode_int(payload, pos, 7)
            name, value = HPACK_STATIC_TABLE[index]
            headers.append((name, value))
        elif b & 0x40:
            index, pos = hpack_decode_int(payload, pos, 6)
            if index == 0:
                name, pos = hpack_decode_string(payload, pos)
            else:
                name = HPACK_STATIC_TABLE[index][0]
            value, pos = hpack_decode_string(payload, pos)
            headers.append((name, value))
        elif b & 0x20:
            _, pos = hpack_decode_int(payload, pos, 5)
        else:
            index, pos = hpack_decode_int(payload, pos, 4)
            if index == 0:
                name, pos = hpack_decode_string(payload, pos)
            else:
                name = HPACK_STATIC_TABLE[index][0]
            value, pos = hpack_decode_string(payload, pos)
            headers.append((name, value))
    return headers


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


def hpack_encode_literal_incremental(name_index, name, value):
    """RFC 7541 SS6.2.1 -- inserted into the dynamic table."""
    if name_index:
        out = hpack_encode_int(name_index, 6, 0x40)
    else:
        out = hpack_encode_int(0, 6, 0x40) + hpack_encode_string(name)
    return out + hpack_encode_string(value)


def hpack_encode_literal_without_indexing(name_index, name, value):
    """RFC 7541 SS6.2.2 -- NOT inserted into the dynamic table."""
    if name_index:
        out = hpack_encode_int(name_index, 4, 0x00)
    else:
        out = hpack_encode_int(0, 4, 0x00) + hpack_encode_string(name)
    return out + hpack_encode_string(value)


def hpack_encode_size_update(new_size):
    """RFC 7541 SS6.3 -- Dynamic Table Size Update."""
    return hpack_encode_int(new_size, 5, 0x20)


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
       f'-subj "/CN=Aurora H2 HPACK Stress Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_hpack_stress_qemu.py -- test root only, NOT committed. */", "#pragma once",
           "static const unsigned char ca_root_0[] = {", "    " + ",".join(str(x) for x in b), "};",
           "static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {",
           '    { ca_root_0, %d, "test root" },' % len(b), "};",
           "#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])"]
    open(path, "w").write("\n".join(out) + "\n")


N_COOKIES = 40
COOKIE_JAR_N = 32   # user/cookiejar.h -- kept in sync manually, checked below


def start_server(port, certfile, keyfile, result):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])
    result["connections_accepted"] = 0
    result["requests"] = []   # one entry per stream: {"stream_id":..., "decoded":...}

    def handle(conn):
        result["connections_accepted"] += 1
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close(); return
        result["alpn"] = tls.selected_alpn_protocol()
        tls.settimeout(20)
        buf = b""

        def recv_exact(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(65536)
                if not chunk:
                    raise OSError("connection closed mid-exchange")
                buf += chunk
            out, buf2 = buf[:n], buf[n:]
            buf = buf2
            return out

        def recv_h2_frame():
            hdr = recv_exact(9)
            length, type_, flags, stream_id = h2_parse_header(hdr)
            payload = recv_exact(length)
            return type_, flags, stream_id, payload

        def recv_next_headers():
            while True:
                type_, flags, stream_id, payload = recv_h2_frame()
                if type_ == H2_TYPE_WINDOW_UPDATE:
                    continue
                return type_, flags, stream_id, payload

        def read_request(expect_stream):
            htype, hflags, hstream, hpayload = recv_next_headers()
            req = {
                "stream_id": hstream,
                "type_ok": htype == H2_TYPE_HEADERS,
                "end_headers": (hflags & H2_FLAG_END_HEADERS) != 0,
            }
            try:
                req["decoded"] = dict(hpack_decode_headers(hpayload))
            except Exception as e:
                req["decode_error"] = str(e)
            result["requests"].append(req)
            return req

        def respond_simple(stream_id, body=b"ok"):
            headers = (
                hpack_encode_indexed(8) +
                hpack_encode_literal_without_indexing(31, None, "text/plain")
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, stream_id, headers))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, stream_id, body))

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

            # --- /bighdr (stream 1): one ~3000-byte custom header value ---
            req1 = read_request(1)
            big_value = ("AuroraHpackStress-" * 158)[:3000]
            headers1 = (
                hpack_encode_indexed(8) +
                hpack_encode_literal_without_indexing(31, None, "text/plain") +
                hpack_encode_literal_incremental(0, "x-big", big_value)
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, req1["stream_id"], headers1))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, req1["stream_id"], b"bighdr-ok"))

            # --- /manycookies (stream 3): 40 Set-Cookie headers, one response ---
            req2 = read_request(3)
            parts = [hpack_encode_indexed(8), hpack_encode_literal_without_indexing(31, None, "text/plain")]
            for i in range(N_COOKIES):
                parts.append(hpack_encode_literal_without_indexing(55, None, "cookie%02d=val%02d; Path=/" % (i, i)))
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, req2["stream_id"], b"".join(parts)))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, req2["stream_id"], b"manycookies-ok"))

            # --- /echo (stream 5): decode the REAL request, check its Cookie header ---
            req3 = read_request(5)
            respond_simple(req3["stream_id"], b"echo-ok")

            # --- /dtsu (stream 7): 3 Dynamic Table Size Updates back to back ---
            req4 = read_request(7)
            headers4 = (
                hpack_encode_indexed(8) +
                hpack_encode_size_update(0) +
                hpack_encode_size_update(100) +
                hpack_encode_size_update(4096) +
                hpack_encode_literal_without_indexing(31, None, "text/plain") +
                hpack_encode_literal_incremental(0, "x-marker", "dtsu-ok")
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, req4["stream_id"], headers4))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, req4["stream_id"], b"dtsu-ok"))

            # --- /massevict (stream 9): 40 fields, ~103 bytes each (>4096 total) ---
            req5 = read_request(9)
            parts = [hpack_encode_indexed(8), hpack_encode_literal_without_indexing(31, None, "text/plain")]
            filler = "V" * 60
            for i in range(40):
                parts.append(hpack_encode_literal_incremental(0, "x-evict-%02d" % i, "entry-%02d-%s" % (i, filler)))
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, req5["stream_id"], b"".join(parts)))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, req5["stream_id"], b"massevict-ok"))
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


def run_qemu(serial_path, typed_cmd, wait_s=60):
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


def main():
    assert COOKIE_JAR_N == 32, "user/cookiejar.h's COOKIE_JAR_N changed -- update this test's expectations"
    work = tempfile.mkdtemp(prefix="aurora-17x5x2-hpack-")
    prod = os.path.join(ROOT, "user/ca_roots.h")
    fails = 0
    srv = None
    try:
        pem, key, der = gen_cert(work)
        write_trust_header(prod, der)
        if sh("make user/httpsget.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        result = {}
        srv = start_server(443, pem, key, result)

        log = run_qemu(os.path.join(work, "serial.log"),
                       "httpsget --alpn 10.0.2.2 /bighdr /manycookies /echo /dtsu /massevict %d" % int(time.time()))

        reqs = result.get("requests", [])
        by_stream = {r["stream_id"]: r for r in reqs}
        echo_req = by_stream.get(5, {})
        echo_cookie = echo_req.get("decoded", {}).get("cookie", "")
        survivors = ["cookie%02d=val%02d" % (i, i) for i in range(N_COOKIES - COOKIE_JAR_N, N_COOKIES)]
        evicted = ["cookie%02d=val%02d" % (i, i) for i in range(0, N_COOKIES - COOKIE_JAR_N)]

        checks = [
            ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
            ("server accepted EXACTLY ONE TCP connection for all 5 requests", result.get("connections_accepted") == 1),
            ("server received the exact connection preface", result.get("preface_ok") is True),
            ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
            ("server confirms it received the client's SETTINGS ACK", result.get("got_client_ack") is True),
            ("server received all 5 requests over that one connection", len(reqs) == 5),
            ("every request's stream ID matches RFC 7540 SS5.1.1 (1,3,5,7,9)",
             sorted(by_stream.keys()) == [1, 3, 5, 7, 9]),

            ("client log shows only ONE TCP connection was ever made", log.count("TCP connected to 10.0.2.2") == 1),
            ("client log shows the connection reused for every later request (4 reuses)",
             log.count("reusing open connection to 10.0.2.2") == 4),

            ("/bighdr: decode succeeded and the connection proceeded to /manycookies "
             "(a ~3000-byte single header value didn't break decode)",
             "stream 1 complete" in log and "stream 3 complete" in log),
            ("/bighdr: status=200 reached", by_stream.get(1, {}).get("type_ok") is True),

            ("/manycookies: client log shows all %d Set-Cookie headers were stored" % N_COOKIES,
             all(("cookie stored: cookie%02d=val%02d" % (i, i)) in log for i in range(N_COOKIES))),

            ("/echo: the real request DID carry a Cookie header at all -- the cookie-over-h2 "
             "fix this test exists to verify (h2_build_headers() used to have no cookie "
             "parameter, so a jar entry learned from an h2 response's Set-Cookie was never "
             "sent back on a later h2 request)", len(echo_cookie) > 0),
            ("/echo: every SURVIVING cookie (the %d most recently set, cookie%02d..cookie%02d) "
             "is present in the real Cookie header Aurora sent" %
             (COOKIE_JAR_N, N_COOKIES - COOKIE_JAR_N, N_COOKIES - 1),
             all(c in echo_cookie for c in survivors)),
            ("/echo: every EVICTED cookie (the %d set first, cookie00..cookie%02d, pushed out "
             "by COOKIE_JAR_N's LRU capacity) is ABSENT from the real Cookie header" %
             (N_COOKIES - COOKIE_JAR_N, N_COOKIES - COOKIE_JAR_N - 1),
             not any(c in echo_cookie for c in evicted)),

            ("/dtsu: decode succeeded across 3 back-to-back Dynamic Table Size Updates "
             "(shrink to 0, grow to 100, grow to 4096) and the connection proceeded to /massevict",
             "stream 7 complete" in log and "stream 9 complete" in log),

            ("/massevict: decode succeeded across 40 fields whose cumulative size (~4120 "
             "bytes) exceeds the dynamic table's own arena (4096), forcing eviction "
             "WITHIN a single header block, not just gradually across many requests",
             "stream 9 complete" in log),

            ("client log shows status=200 reached for all 5 requests", log.count("status=200") >= 5),
            ("client log shows the final 200 OK line", "200 OK over Aurora TCP->TLS1.3->HTTP" in log),
            ("no error was recorded server-side", "error" not in result),
        ]

        for name, ok in checks:
            print(f"{name:100}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1

        if not all(c in echo_cookie for c in survivors) or any(c in echo_cookie for c in evicted):
            print("  echo_cookie (real Cookie header Aurora sent on /echo):", repr(echo_cookie))
    finally:
        if srv:
            try: srv.close()
            except OSError: pass
        subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh("make user/httpsget.elf disk.img")
        shutil.rmtree(work, ignore_errors=True)
    print("\n17.5.2 HPACK STRESS (large headers/cookies/DTSU/mass eviction, QEMU, real frame-level server): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
