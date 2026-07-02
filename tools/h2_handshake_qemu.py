#!/usr/bin/env python3
"""Phase 17.1.1/17.1.2/17.1.3 acceptance: the HTTP/2 connection-
establishment handshake (RFC 7540 §3.5/§6.5), the generic frame reader and
DATA frame support (17.1.2), and a real, HPACK-compressed HEADERS request
using only RFC 7541's static table (17.1.3) -- negotiated for real inside
QEMU against a genuine TLS 1.3 server that speaks real HTTP/2 frames (and
now real HPACK) at the byte level, hand-rolled here in Python, independent
of Aurora's own http2/frame.c and http2/hpack.c -- this script's frame and
HPACK encoders/decoders are from-scratch second implementations, not a
copy, so a bug shared between the two wouldn't hide behind agreement.

One QEMU boot: `httpsget --alpn 10.0.2.2 /whatever <now>` against a server
whose own ALPN list is `["h2"]` only, forcing the selection (this script
only cares about the h2 path -- see tools/alpn_qemu.py for the ALPN
selection matrix itself). The server:

  1. Reads the connection preface (24 bytes) and confirms it's exactly
     "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" -- not just "some bytes arrived".
  2. Reads the client's SETTINGS frame and confirms it's really type=
     SETTINGS, non-ACK, empty (Aurora's own choice: no special preferences).
  3. Sends its OWN SETTINGS frame back -- deliberately non-empty (one real
     parameter), unlike Aurora's, to prove the client's frame reader
     correctly skips an arbitrary-length payload, not just a zero-length
     one -- followed immediately by a WINDOW_UPDATE frame (a connection-
     level flow-control bump many real HTTP/2 servers send unprompted right
     after their SETTINGS), to prove Aurora's "skip anything that isn't one
     of the two frames it's waiting for" logic really does tolerate an
     unrelated frame type interleaved in the middle of the exchange, not
     just extra bytes of a *known* type.
  4. Sends a stray, PADDED, END_STREAM DATA frame on a stream nothing ever
     opened (Phase 17.1.2): this is the real point of this step -- the
     generic frame reader now decodes a genuine, payload-bearing, padded
     frame type correctly (Aurora's own log names it: "DATA frame seen"),
     not just tolerates extra bytes of a frame type it already recognized
     like the WINDOW_UPDATE above.
  5. Waits for Aurora's SETTINGS ACK (type=SETTINGS, flags=ACK, empty) and
     confirms it arrives.
  6. Sends its own SETTINGS ACK, acknowledging Aurora's SETTINGS from step 2.
  7. Reads Aurora's real HEADERS frame (Phase 17.1.3) -- stream 1,
     END_HEADERS + END_STREAM set -- and genuinely HPACK-decodes its
     payload (this script's own decoder), confirming the actual :method,
     :scheme, :authority, :path and user-agent Aurora chose to send, not
     just that *some* bytes shaped like a HEADERS frame arrived.
  8. Sends back a minimal real response -- a HEADERS frame carrying just
     ":status: 200" (itself a single indexed static-table byte).
  9. Confirms NO further bytes ever arrive afterward -- there is still no
     response *decoding*, so even though Aurora just received a real
     HTTP/2 response to a request it genuinely sent, it recognizes the
     response frame by type and stops there, not acting on its (HPACK-
     compressed) contents.

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_handshake_qemu.py
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
H2_FLAG_PADDED = 8

# HPACK static table (RFC 7541 Appendix A) -- only the entries this test
# actually needs to decode or send. A from-scratch second decoder, wholly
# independent of Aurora's own http2/hpack.c, for the same "a bug shared
# between two independent implementations is a lot less likely" reason
# h2_frame()/h2_data_frame() above are independent of http2/frame.c.
HPACK_STATIC_TABLE = {
    1: (":authority", None),
    2: (":method", "GET"),
    3: (":method", "POST"),
    4: (":path", "/"),
    6: (":scheme", "http"),
    7: (":scheme", "https"),
    8: (":status", "200"),
    58: ("user-agent", None),
}


def hpack_decode_int(data, pos, prefix_bits):
    """RFC 7541 SS5.1. Returns (value, new_pos)."""
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
    """RFC 7541 SS5.2. Returns (str, new_pos). Huffman not implemented --
    neither this test's own responses nor Aurora (Phase 17.1.3) ever send
    a Huffman-coded string, so a Huffman-flagged string here would itself
    be a test failure worth raising loudly, not silently handling."""
    b = data[pos]
    if b & 0x80:
        raise ValueError("unexpected Huffman-coded string (Phase 17.1.3 never sends one)")
    length, pos = hpack_decode_int(data, pos, 7)
    raw = bytes(data[pos:pos + length])
    return raw.decode("latin1"), pos + length


def hpack_decode_headers(payload):
    """RFC 7541 SS6: walks Indexed (SS6.1), Literal with Incremental
    Indexing (SS6.2.1), Literal without Indexing (SS6.2.2), and Literal
    Never Indexed (SS6.2.3) representations -- everything a real encoder
    could produce, even though Aurora (Phase 17.1.3) only ever emits the
    first two. Returns a list of (name, value) tuples in wire order."""
    headers = []
    pos = 0
    while pos < len(payload):
        b = payload[pos]
        if b & 0x80:                                  # Indexed Header Field
            index, pos = hpack_decode_int(payload, pos, 7)
            name, value = HPACK_STATIC_TABLE[index]
            headers.append((name, value))
        elif b & 0x40:                                 # Literal with Incremental Indexing
            index, pos = hpack_decode_int(payload, pos, 6)
            name = HPACK_STATIC_TABLE[index][0] if index else None
            if index == 0:
                name, pos = hpack_decode_string(payload, pos)
            value, pos = hpack_decode_string(payload, pos)
            headers.append((name, value))
        elif b & 0x20:                                  # Dynamic Table Size Update
            _, pos = hpack_decode_int(payload, pos, 5)
        else:                                            # Literal without/never indexed (0000/0001)
            index, pos = hpack_decode_int(payload, pos, 4)
            if index == 0:
                name, pos = hpack_decode_string(payload, pos)
            else:
                name = HPACK_STATIC_TABLE[index][0]
            value, pos = hpack_decode_string(payload, pos)
            headers.append((name, value))
    return headers


def hpack_encode_indexed(index):
    return bytes([0x80 | index])


def h2_frame(type_, flags, stream_id, payload=b""):
    length = len(payload)
    return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
                  type_, flags]) + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload


def h2_data_frame(stream_id, data, padding=0, end_stream=False):
    """A real, padded DATA frame (RFC 7540 SS6.1): [pad_len][data][padding]."""
    flags = (H2_FLAG_END_STREAM if end_stream else 0) | (H2_FLAG_PADDED if padding else 0)
    payload = (bytes([padding]) if padding else b"") + data + (b"\x00" * padding)
    return h2_frame(H2_TYPE_DATA, flags, stream_id, payload)


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
       f'-subj "/CN=Aurora H2 Handshake Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_handshake_qemu.py -- test root only, NOT committed. */", "#pragma once",
           "static const unsigned char ca_root_0[] = {", "    " + ",".join(str(x) for x in b), "};",
           "static const struct { const unsigned char *der; unsigned len; const char *name; } ca_roots[] = {",
           '    { ca_root_0, %d, "test root" },' % len(b), "};",
           "#define CA_ROOTS_N (sizeof ca_roots / sizeof ca_roots[0])"]
    open(path, "w").write("\n".join(out) + "\n")


def start_server(port, certfile, keyfile, result):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])   # only h2 available -- forces the selection

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
                    raise OSError("connection closed mid-handshake")
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out

        try:
            preface = recv_exact(len(H2_PREFACE))
            result["preface_ok"] = (preface == H2_PREFACE)

            hdr = recv_exact(9)
            length, type_, flags, _stream_id = h2_parse_header(hdr)
            recv_exact(length)   # the (empty) SETTINGS payload itself
            result["client_settings_ok"] = (type_ == H2_TYPE_SETTINGS and flags == 0 and length == 0)

            # Our own SETTINGS: deliberately non-empty (one real parameter --
            # SETTINGS_MAX_CONCURRENT_STREAMS=100), to prove the client skips
            # an arbitrary-length payload correctly, not just a zero-length one.
            settings_payload = struct.pack(">HI", 0x3, 100)
            tls.sendall(h2_frame(H2_TYPE_SETTINGS, 0, 0, settings_payload))
            # A connection-level WINDOW_UPDATE right after SETTINGS, unprompted
            # -- common in real servers, and exactly the "frame type the client
            # isn't specifically waiting for" case its skip logic needs to
            # tolerate mid-handshake, not just before or after it.
            tls.sendall(h2_frame(H2_TYPE_WINDOW_UPDATE, 0, 0, struct.pack(">I", 65535)))
            # A stray, PADDED, END_STREAM DATA frame on a stream nothing ever
            # opened (Phase 17.1.2's whole point: the generic frame reader now
            # decodes a real, payload-bearing, padded frame type correctly --
            # not just tolerates extra bytes of a frame type it already knew
            # about, like the empty SETTINGS/WINDOW_UPDATE above).
            tls.sendall(h2_data_frame(1, b"unsolicited body", padding=5, end_stream=True))

            hdr2 = recv_exact(9)
            length2, type2, flags2, _s2 = h2_parse_header(hdr2)
            result["got_client_ack"] = (type2 == H2_TYPE_SETTINGS and flags2 == H2_FLAG_ACK and length2 == 0)

            # Acknowledge the client's own SETTINGS.
            tls.sendall(h2_frame(H2_TYPE_SETTINGS, H2_FLAG_ACK, 0))

            # Phase 17.1.3: Aurora now sends a real HEADERS frame opening a
            # genuine request -- read and HPACK-decode it for real (this
            # test's own from-scratch decoder, independent of Aurora's own
            # http2/hpack.c), confirming the actual pseudo-headers it chose.
            hhdr = recv_exact(9)
            hlength, htype, hflags, hstream = h2_parse_header(hhdr)
            hpayload = recv_exact(hlength)
            result["headers_frame_ok"] = (htype == H2_TYPE_HEADERS and hstream == 1 and
                                          (hflags & H2_FLAG_END_HEADERS) != 0 and
                                          (hflags & H2_FLAG_END_STREAM) != 0)
            try:
                decoded = dict(hpack_decode_headers(hpayload))
                result["decoded_headers"] = decoded
            except Exception as e:
                result["hpack_decode_error"] = str(e)
                decoded = {}

            # A minimal real response: just ":status: 200", itself a single
            # indexed static-table byte (index 8) -- proving the round trip
            # without needing this test to build a bigger response than the
            # point requires.
            tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1,
                                 hpack_encode_indexed(8)))

            # Nothing more should ever arrive: Aurora recognizes the response
            # frame by type and stops -- it doesn't (can't yet) act on it.
            try:
                extra = tls.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                extra = b""
            result["extra_after_handshake"] = extra
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
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
    return open(serial_path, errors="replace").read() if os.path.exists(serial_path) else ""


def main():
    work = tempfile.mkdtemp(prefix="aurora-17x1x1-")
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

        log = run_qemu(serial, "httpsget --alpn 10.0.2.2 /whatever %d" % int(time.time()))

        checks = [
            ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
            ("server received the exact 24-byte connection preface", result.get("preface_ok") is True),
            ("server confirms the client's SETTINGS is real (type=SETTINGS, non-ACK, empty)",
             result.get("client_settings_ok") is True),
            ("client log shows the preface + SETTINGS were sent",
             "connection preface + SETTINGS sent" in log),
            ("client log shows the server's SETTINGS was received",
             "server SETTINGS received" in log),
            ("client log shows the stray padded DATA frame was correctly recognized as DATA "
             "(not confused with the WINDOW_UPDATE or SETTINGS around it)",
             "DATA frame seen (stream 1," in log),
            ("client log shows our SETTINGS ACK was sent", "SETTINGS ACK sent" in log),
            ("server confirms it actually received that SETTINGS ACK", result.get("got_client_ack") is True),
            ("client log shows the server's SETTINGS ACK (for ours) was recognized",
             "our SETTINGS was ACKed" in log),
            ("client log shows the connection-establishment handshake completed",
             "connection-establishment handshake complete" in log),
            ("client log shows the real HEADERS frame was sent", "HEADERS frame sent (stream 1, GET" in log),
            ("server confirms it's a real HEADERS frame (stream 1, END_HEADERS+END_STREAM set)",
             result.get("headers_frame_ok") is True),
            ("server's independent HPACK decoder decoded it without error", "hpack_decode_error" not in result),
            ("decoded :method is GET", result.get("decoded_headers", {}).get(":method") == "GET"),
            ("decoded :scheme is https", result.get("decoded_headers", {}).get(":scheme") == "https"),
            ("decoded :path is /whatever (the real requested path, not a placeholder)",
             result.get("decoded_headers", {}).get(":path") == "/whatever"),
            ("decoded :authority is 10.0.2.2 (the real host)",
             result.get("decoded_headers", {}).get(":authority") == "10.0.2.2"),
            ("decoded user-agent is Aurora's own", result.get("decoded_headers", {}).get("user-agent", "").startswith("Aurora-httpsget")),
            ("client log shows a response frame was seen and named by type",
             "response frame seen (HEADERS, stream 1," in log),
            ("client log shows the final refusal to complete a real fetch, now for the right "
             "reason (response decoding, not \"no HEADERS framing\")",
             "response decoding needs HPACK Huffman/dynamic table support" in log),
            ("status=200 was never reached (nothing decodes the response body yet)", "status=200" not in log),
            ("server confirms NOTHING further arrived after its response", result.get("extra_after_handshake") == b""),
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
    print("\n17.1.1 HTTP/2 CONNECTION-ESTABLISHMENT HANDSHAKE (QEMU, real frame-level server): " +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
