#!/usr/bin/env python3
"""Phase 17.4.1 acceptance: an HTTP/2 request that carries a real body
(POST/PUT/PATCH, the same three methods the 16.1/16.5 HTTP/1.1 path
already supports), negotiated for real inside QEMU against a genuine TLS
1.3 server that speaks real HTTP/2 frames and real HPACK, hand-rolled here
in Python -- independent of Aurora's own http2/*.c, the same "a bug shared
between two independent implementations is a lot less likely" reasoning
tools/h2_handshake_qemu.py already established. This script duplicates
(not imports) that script's own frame/HPACK helpers, matching this
project's convention of every QEMU test script being self-contained.

One QEMU boot: `httpsget --alpn --method POST 10.0.2.2 /submit
field1=value1 <now>` against a server whose own ALPN list is `["h2"]`
only. The server:

  1. Completes a minimal connection-establishment handshake (preface,
     SETTINGS exchange in both directions) -- the handshake itself is
     already exhaustively covered by tools/h2_handshake_qemu.py; this
     script keeps it minimal since the point here is the request BODY.
  2. Reads Aurora's HEADERS frame and confirms END_STREAM is CLEAR on it
     (Phase 17.4.1's whole point: a body follows, so this request's own
     HEADERS frame must NOT claim the stream ended there).
  3. HPACK-decodes that HEADERS frame (this script's own from-scratch
     decoder) and confirms :method is POST, and that a real Content-Type
     and Content-Length (matching the real body length, not a placeholder)
     were both sent -- Phase 17.4.1's own new headers.
  4. Reads the DATA frame that follows and confirms END_STREAM IS set on
     it, and that its payload is the EXACT real body bytes ("field1=
     value1"), not a placeholder or empty frame.
  5. Sends back a real response (status 200 plus a short body), so the
     script can also confirm Aurora's read path still works correctly
     after having just sent a body-bearing request -- proving the two
     directions don't interfere with each other on the same stream.

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_post_qemu.py
"""
import os, socket, ssl, struct, subprocess, sys, tempfile, threading, time, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_TYPE_DATA = 0
H2_TYPE_HEADERS = 1
H2_TYPE_SETTINGS = 4
H2_FLAG_ACK = 1
H2_FLAG_END_STREAM = 1
H2_FLAG_END_HEADERS = 4

# HPACK static table (RFC 7541 Appendix A) -- only the entries this test
# actually needs, a from-scratch second decoder wholly independent of
# Aurora's own http2/hpack_table.c.
HPACK_STATIC_TABLE = {
    1: (":authority", None),
    2: (":method", "GET"),
    3: (":method", "POST"),
    4: (":path", "/"),
    7: (":scheme", "https"),
    28: ("content-length", None),
    31: ("content-type", None),
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
        raise ValueError("unexpected Huffman-coded string (this test's own request never sends one)")
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
       f'-subj "/CN=Aurora H2 POST Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_post_qemu.py -- test root only, NOT committed. */", "#pragma once",
           "static const unsigned char ca_root_0[] = {", "    " + ",".join(str(x) for x in b), "};",
           "static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {",
           '    { ca_root_0, %d, "test root" },' % len(b), "};",
           "#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])"]
    open(path, "w").write("\n".join(out) + "\n")


def start_server(port, certfile, keyfile, result):
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
        tls.settimeout(10)
        buf = b""

        def recv_exact(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(4096)
                if not chunk:
                    raise OSError("connection closed mid-exchange")
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out

        try:
            preface = recv_exact(len(H2_PREFACE))
            result["preface_ok"] = (preface == H2_PREFACE)

            hdr = recv_exact(9)
            length, type_, _flags, _sid = h2_parse_header(hdr)
            recv_exact(length)   # client's (empty) SETTINGS payload
            result["client_settings_ok"] = (type_ == H2_TYPE_SETTINGS and length == 0)

            tls.sendall(h2_frame(H2_TYPE_SETTINGS, 0, 0))          # our SETTINGS (empty is fine)
            hdr2 = recv_exact(9)
            length2, type2, flags2, _s2 = h2_parse_header(hdr2)
            result["got_client_ack"] = (type2 == H2_TYPE_SETTINGS and flags2 == H2_FLAG_ACK and length2 == 0)
            tls.sendall(h2_frame(H2_TYPE_SETTINGS, H2_FLAG_ACK, 0))  # ack the client's SETTINGS

            # Phase 17.4.1: the real HEADERS frame for a body-bearing
            # request -- END_STREAM must be CLEAR here (a body follows).
            hhdr = recv_exact(9)
            hlength, htype, hflags, hstream = h2_parse_header(hhdr)
            hpayload = recv_exact(hlength)
            result["headers_frame_ok"] = (htype == H2_TYPE_HEADERS and hstream == 1 and
                                          (hflags & H2_FLAG_END_HEADERS) != 0)
            result["headers_end_stream_clear"] = (hflags & H2_FLAG_END_STREAM) == 0
            try:
                decoded = dict(hpack_decode_headers(hpayload))
                result["decoded_headers"] = decoded
            except Exception as e:
                result["hpack_decode_error"] = str(e)
                decoded = {}

            # The DATA frame carrying the real request body -- END_STREAM
            # must be SET here instead.
            dhdr = recv_exact(9)
            dlength, dtype, dflags, dstream = h2_parse_header(dhdr)
            dpayload = recv_exact(dlength)
            result["data_frame_ok"] = (dtype == H2_TYPE_DATA and dstream == 1)
            result["data_end_stream_set"] = (dflags & H2_FLAG_END_STREAM) != 0
            result["received_body"] = dpayload

            # A real response, so Aurora's read path is proven to still
            # work correctly right after it just sent a body-bearing
            # request on the very same stream.
            resp_body = "stored"
            headers_payload = (
                hpack_encode_literal_incremental(8, None, "200") +
                hpack_encode_literal_incremental(31, None, "text/plain")
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1, headers_payload))
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, 1, resp_body.encode()))
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


def run_qemu(serial_path, typed_cmd, wait_s=25):
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
        km = {" ": "spc", ".": "dot", "/": "slash", "-": "minus", "=": "equal"}
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
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-17x4x1-")
    prod = os.path.join(ROOT, "user/ca_roots.h")
    serial = os.path.join(work, "serial.log")
    fails = 0
    srv = None
    try:
        pem, key, der = gen_cert(work)
        write_trust_header(prod, der)
        if sh("make user/httpsget.elf disk.img").returncode != 0:
            print("build FAILED"); return 1

        result = {}
        srv = start_server(443, pem, key, result)

        log = run_qemu(serial, "httpsget --alpn --method POST 10.0.2.2 /submit field1=value1 %d" % int(time.time()))

        body = b"field1=value1"
        checks = [
            ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
            ("server received the exact 24-byte connection preface", result.get("preface_ok") is True),
            ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
            ("server confirms it received the client's SETTINGS ACK", result.get("got_client_ack") is True),
            ("server confirms a real HEADERS frame arrived (stream 1, END_HEADERS set)",
             result.get("headers_frame_ok") is True),
            ("server confirms END_STREAM is CLEAR on the HEADERS frame (a body follows)",
             result.get("headers_end_stream_clear") is True),
            ("server's independent HPACK decoder decoded the HEADERS without error",
             "hpack_decode_error" not in result),
            ("decoded :method is POST", result.get("decoded_headers", {}).get(":method") == "POST"),
            ("decoded content-type is present (not omitted for a body-bearing request)",
             bool(result.get("decoded_headers", {}).get("content-type"))),
            ("decoded content-length matches the REAL body length (not a placeholder)",
             result.get("decoded_headers", {}).get("content-length") == str(len(body))),
            ("server confirms a real DATA frame arrived on stream 1", result.get("data_frame_ok") is True),
            ("server confirms END_STREAM IS set on the DATA frame (the body's own last frame)",
             result.get("data_end_stream_set") is True),
            ("server received the EXACT real body bytes, not a placeholder or truncated copy",
             result.get("received_body") == body),
            ("client log shows the combined HEADERS+DATA request was sent",
             "HEADERS+DATA frame sent (stream 1, POST /submit)" in log),
            ("client log shows the response HEADERS were HPACK-decoded",
             "HEADERS decoded" in log),
            ("client log shows status=200 was reached (the read path still works after sending a body)",
             "status=200" in log),
            ("client log shows the final 200 OK line", "200 OK over Aurora TCP->TLS1.3->HTTP" in log),
            ("no error was recorded server-side", "error" not in result),
        ]

        for name, ok in checks:
            print(f"{name:80}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1
    finally:
        if srv:
            try: srv.close()
            except OSError: pass
        subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh("make user/httpsget.elf disk.img")
        shutil.rmtree(work, ignore_errors=True)
    print("\n17.4.1 HTTP/2 REQUEST BODY (QEMU, real frame-level server): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
