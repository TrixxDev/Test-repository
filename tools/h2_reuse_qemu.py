#!/usr/bin/env python3
"""Phase 17.4.2 acceptance: reusing ONE HTTP/2 connection for a SEQUENCE of
requests (never concurrent/multiplexed), negotiated for real inside QEMU
against a genuine TLS 1.3 server that speaks real HTTP/2 frames and real
HPACK, hand-rolled here in Python -- independent of Aurora's own
http2/*.c, matching every other h2 QEMU test in this suite.

One QEMU boot: `httpsget --alpn 10.0.2.2 /a /b <now>` -- TWO paths on the
SAME host, which httpsget's own CLI already fetches sequentially via two
fetch_one() calls. The server:

  1. Accepts exactly ONE TCP connection for the whole run -- the entire
     point of this phase. A second accept() would mean Aurora reconnected
     instead of reusing, silently defeating 17.4.2's own goal.
  2. Completes a minimal handshake (preface, SETTINGS exchange).
  3. Reads the FIRST request's HEADERS frame and confirms it's really on
     stream 1 (RFC 7540 §5.1.1's first client-initiated stream) for
     /a, then answers with a HEADERS frame that adds :status and
     content-type to ITS OWN dynamic table via "Literal Header Field with
     Incremental Indexing" (RFC 7541 §6.2.1), plus a DATA frame with a
     distinct body.
  4. Reads the SECOND request's HEADERS frame -- on the SAME TCP+TLS
     connection, no new handshake -- and confirms it's on stream 3, not
     another stream 1, for /b. Answers this one referencing BOTH of the
     previous response's dynamic-table entries purely by INDEX (RFC 7541
     §6.1's "Indexed Header Field", no literal bytes for :status or
     content-type at all this time) -- proving Aurora's own decode-side
     dynamic table (session_slot.h2_dyn_table) genuinely persisted across
     the two requests, not just within one. A different DATA body proves
     the two responses aren't being confused with each other.

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_reuse_qemu.py
"""
import os, socket, ssl, struct, subprocess, sys, tempfile, threading, time, shutil
from qemu_serial import run_qemu_serial

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_TYPE_DATA = 0
H2_TYPE_HEADERS = 1
H2_TYPE_SETTINGS = 4
H2_FLAG_ACK = 1
H2_FLAG_END_STREAM = 1
H2_FLAG_END_HEADERS = 4

HPACK_STATIC_TABLE = {
    1: (":authority", None),
    2: (":method", "GET"),
    4: (":path", "/"),
    7: (":scheme", "https"),
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
       f'-subj "/CN=Aurora H2 Reuse Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_reuse_qemu.py -- test root only, NOT committed. */", "#pragma once",
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
    result["connections_accepted"] = 0
    result["requests"] = []

    def handle(conn):
        result["connections_accepted"] += 1
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

        def recv_h2_frame():
            hdr = recv_exact(9)
            length, type_, flags, stream_id = h2_parse_header(hdr)
            payload = recv_exact(length)
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

            # --- Request 1 (expected stream 1, path /a) ---
            htype, hflags, hstream, hpayload = recv_h2_frame()
            req1 = {
                "type_ok": htype == H2_TYPE_HEADERS,
                "stream_id": hstream,
                "end_headers": (hflags & H2_FLAG_END_HEADERS) != 0,
            }
            try:
                req1["decoded"] = dict(hpack_decode_headers(hpayload))
            except Exception as e:
                req1["error"] = str(e)
            result["requests"].append(req1)

            # Response 1: :status and content-type BOTH added to the
            # server's own dynamic table via incremental indexing --
            # content-type is inserted LAST, so it becomes index 62 and
            # :status becomes index 63 (RFC 7541 SS2.3.3: most-recent-first).
            headers1 = (
                hpack_encode_literal_incremental(8, None, "200") +
                hpack_encode_literal_incremental(31, None, "text/plain")
            )
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1, headers1))
            body1 = b"first response body"
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, 1, body1))

            # --- Request 2 (expected stream 3, path /b, SAME connection) ---
            htype, hflags, hstream, hpayload = recv_h2_frame()
            req2 = {
                "type_ok": htype == H2_TYPE_HEADERS,
                "stream_id": hstream,
                "end_headers": (hflags & H2_FLAG_END_HEADERS) != 0,
            }
            try:
                req2["decoded"] = dict(hpack_decode_headers(hpayload))
            except Exception as e:
                req2["error"] = str(e)
            result["requests"].append(req2)

            # Response 2: :status (index 63) and content-type (index 62)
            # referenced PURELY by index -- no literal bytes for either --
            # only decodable correctly if Aurora's own dynamic table still
            # has both entries from response 1, on this SAME connection.
            headers2 = hpack_encode_indexed(63) + hpack_encode_indexed(62)
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, 3, headers2))
            body2 = b"second response body"
            tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, 3, body2))
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


def main():
    work = tempfile.mkdtemp(prefix="aurora-17x4x2-")
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

        log = run_qemu_serial("httpsget --alpn 10.0.2.2 /a /b %d" % int(time.time()), wait_s=35)

        reqs = result.get("requests", [])
        req1 = reqs[0] if len(reqs) > 0 else {}
        req2 = reqs[1] if len(reqs) > 1 else {}

        checks = [
            ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
            ("server accepted EXACTLY ONE TCP connection for both requests", result.get("connections_accepted") == 1),
            ("server received the exact connection preface", result.get("preface_ok") is True),
            ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
            ("server confirms it received the client's SETTINGS ACK", result.get("got_client_ack") is True),
            ("request 1: a real HEADERS frame arrived", req1.get("type_ok") is True),
            ("request 1: opened on stream 1 (RFC 7540 SS5.1.1's first client stream)", req1.get("stream_id") == 1),
            ("request 1: decoded :path is /a", req1.get("decoded", {}).get(":path") == "/a"),
            ("request 2: a real HEADERS frame arrived on the SAME connection", req2.get("type_ok") is True),
            ("request 2: opened on stream 3, NOT another stream 1", req2.get("stream_id") == 3),
            ("request 2: decoded :path is /b", req2.get("decoded", {}).get(":path") == "/b"),
            ("client log shows only ONE TCP connection was ever made", log.count("TCP connected to 10.0.2.2") == 1),
            ("client log shows the connection being genuinely reused (not reconnected) for /b",
             "reusing open connection to 10.0.2.2" in log),
            ("client log shows stream 1 completed", "stream 1 complete" in log),
            ("client log shows stream 3 completed (not a second stream 1)", "stream 3 complete" in log),
            ("client log shows response 1's real body content", "first response body" in log),
            ("client log shows response 2's real body content -- only decodable if Aurora's own "
             "dynamic table still had both entries from response 1 on this same connection",
             "second response body" in log),
            # Once from h2_fetch()'s own "stream N complete" diagnostic and
            # once from fetch_one()'s status line, for EACH of the 2 paths.
            ("client log shows status=200 reached for both paths (4 occurrences: 2 lines each x 2 paths)",
             log.count("status=200") == 4),
            ("client log shows the final 200 OK line at least once", "200 OK over Aurora TCP->TLS1.3->HTTP" in log),
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
    print("\n17.4.2 HTTP/2 CONNECTION REUSE (QEMU, real frame-level server): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
