#!/usr/bin/env python3
"""Phase 17.5.2 acceptance (item 2, "long-lived connections"): hundreds of
SEQUENTIAL requests over a SINGLE HTTP/2 connection, negotiated for real
inside QEMU against a genuine TLS 1.3 server that speaks real HTTP/2 frames
and real HPACK, hand-rolled here in Python -- independent of Aurora's own
http2/*.c, matching every other h2 QEMU test in this suite.

Aurora's own shell (user/sh.c) caps a typed command line at ARG_MAX (16)
tokens, so "one path argument per request" (the mechanism every earlier h2
QEMU test used for 2-3 requests) cannot reach "hundreds". Phase 17.5.2 adds
httpsget's own `--repeat N` flag for exactly this: one short typed command
-- `httpsget --alpn --repeat N 10.0.2.2 /r <now>` -- drives N sequential
fetch_one() calls of the SAME path, reusing whatever session_slot the first
one opened exactly as repeating that path N times in argv already would
(Phase 17.4.2's connection-reuse logic doesn't know or care whether the
repeated fetch came from a longer argv or a loop around one path).

N_REQUESTS below is chosen to exercise three things the user explicitly
asked for, deliberately not just "N is a big round number":

  1. Stream IDs: RFC 7540 SS5.1.1 client-initiated streams are always odd
     and strictly increasing -- this test's server verifies EVERY one of
     the N requests lands on exactly the expected stream (1, 3, 5, ...,
     2N-1), not just the first couple as the smaller 17.4.2 reuse test did.
  2. HPACK dynamic table growth AND eviction over many exchanges: each
     response inserts one NEW dynamic-table entry ("x-req-id: <n>", via
     Incremental Indexing, RFC 7541 SS6.2.1) that no earlier or later
     response ever repeats, so decoding response N+1 correctly is only
     possible if Aurora's dynamic table still holds exactly the right state
     left behind by every response before it. HPACK_DYN_ARENA_SIZE (4096
     bytes) holds roughly 95 such ~42-byte entries before RFC 7541 SS4.4
     eviction has to start kicking the oldest entry out to make room for
     the newest -- with N_REQUESTS comfortably past that, most of this
     run's responses are decoded only correctly if eviction itself (not
     just insertion) has been correct for hundreds of cycles in a row.
  3. Multiple WINDOW_UPDATE cycles: RFC 7540 SS6.9.1's connection-level
     window is shared across the WHOLE connection's lifetime, not reset
     per stream -- so unlike 17.4.3's single-large-response test (one
     stream, one climb to the threshold), this test's window drains a
     little on EVERY one of many small responses, crossing the 50%
     replenishment threshold repeatedly over the run.

Self-contained and reproducible: no private keys are committed; the
production user/ca_roots.h is restored on exit. Requires: qemu-system-i386,
openssl, the cross toolchain. Run from the repo root:
python3 tools/h2_longlived_qemu.py
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

N_REQUESTS = 300          # "hundreds", per the user's own wording
BODY_LEN = 2048            # per response -- small individually, but N_REQUESTS of
                            # them cumulatively cross the 65535-byte default
                            # connection window many times over (see doc comment)


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
    """RFC 7541 SS6.2.2 -- NOT inserted into the dynamic table; used here for
    content-type so the only entry each response adds is its own x-req-id."""
    if name_index:
        out = hpack_encode_int(name_index, 4, 0x00)
    else:
        out = hpack_encode_int(0, 4, 0x00) + hpack_encode_string(name)
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
       f'-subj "/CN=Aurora H2 Long-Lived Test" -addext "basicConstraints=critical,CA:FALSE" '
       f'-addext "keyUsage=critical,digitalSignature" -addext "subjectAltName=DNS:10.0.2.2"')
    sh(f"openssl x509 -in {pem} -outform DER -out {der}")
    return pem, key, der


def write_trust_header(path, root_der):
    b = open(root_der, "rb").read()
    out = ["/* GENERATED by h2_longlived_qemu.py -- test root only, NOT committed. */", "#pragma once",
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
    result["requests"] = []           # one entry per request: {"stream_id":..., "type_ok":..., "end_headers":...}
    result["window_updates"] = []     # (stream_id, increment) for every WINDOW_UPDATE seen, in arrival order

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
            out, buf = buf[:n], buf[n:]
            return out

        def recv_h2_frame():
            hdr = recv_exact(9)
            length, type_, flags, stream_id = h2_parse_header(hdr)
            payload = recv_exact(length)
            return type_, flags, stream_id, payload

        def recv_next_headers():
            """Skip over any WINDOW_UPDATE frames Aurora sent since the last
            response (flow control, Phase 17.4.3/17.5.2) and return the next
            real HEADERS frame -- exactly what Aurora's own h2_fetch() does
            for frames that aren't for its current stream."""
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

            for i in range(N_REQUESTS):
                htype, hflags, hstream, _hpayload = recv_next_headers()
                result["requests"].append({
                    "type_ok": htype == H2_TYPE_HEADERS,
                    "stream_id": hstream,
                    "end_headers": (hflags & H2_FLAG_END_HEADERS) != 0,
                })

                # :status via the static table (index 8, no growth); content-type
                # via "without indexing" (RFC 7541 SS6.2.2, no growth either); and
                # exactly ONE new dynamic-table entry per response -- x-req-id,
                # a name+value this exact response has never sent before, so it
                # can ONLY decode correctly on a table that's tracked every prior
                # insertion (and every eviction once the arena fills) correctly.
                headers = (
                    hpack_encode_indexed(8) +
                    hpack_encode_literal_without_indexing(31, None, "text/plain") +
                    hpack_encode_literal_incremental(0, "x-req-id", str(i))
                )
                tls.sendall(h2_frame(H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, hstream, headers))
                body = bytes((i + j) % 256 for j in range(BODY_LEN))
                tls.sendall(h2_frame(H2_TYPE_DATA, H2_FLAG_END_STREAM, hstream, body))

            # Drain whatever final WINDOW_UPDATE(s) trail the last response.
            tls.settimeout(3)
            while True:
                try:
                    wtype, _wflags, wstream, wpayload = recv_h2_frame()
                except (socket.timeout, OSError):
                    break
                if wtype == H2_TYPE_WINDOW_UPDATE and len(wpayload) == 4:
                    increment = ((wpayload[0] & 0x7F) << 24) | (wpayload[1] << 16) | (wpayload[2] << 8) | wpayload[3]
                    result["window_updates"].append((wstream, increment))
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


def run_qemu(serial_path, typed_cmd, wait_s=240):
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
    work = tempfile.mkdtemp(prefix="aurora-17x5x2-longlived-")
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

        log = run_qemu(serial, "httpsget --alpn --repeat %d 10.0.2.2 /r %d" % (N_REQUESTS, int(time.time())))

        reqs = result.get("requests", [])
        expected_streams = [1 + 2 * i for i in range(N_REQUESTS)]
        got_streams = [r.get("stream_id") for r in reqs]
        all_type_ok = all(r.get("type_ok") for r in reqs)
        all_end_headers = all(r.get("end_headers") for r in reqs)

        wus = result.get("window_updates", [])
        conn_level = [inc for sid, inc in wus if sid == 0]

        checks = [
            ("ALPN negotiated \"h2\"", result.get("alpn") == "h2"),
            ("server accepted EXACTLY ONE TCP connection for all %d requests" % N_REQUESTS,
             result.get("connections_accepted") == 1),
            ("server received the exact connection preface", result.get("preface_ok") is True),
            ("server confirms the client's SETTINGS is real and empty", result.get("client_settings_ok") is True),
            ("server confirms it received the client's SETTINGS ACK", result.get("got_client_ack") is True),
            ("server received all %d requests" % N_REQUESTS, len(reqs) == N_REQUESTS),
            ("every request was a real HEADERS frame with END_HEADERS set", all_type_ok and all_end_headers),
            ("every request's stream ID matches RFC 7540 SS5.1.1 (odd, strictly increasing: "
             "1, 3, 5, ..., %d)" % expected_streams[-1] if reqs else "n/a", got_streams == expected_streams),
            ("server received at least 5 distinct CONNECTION-level WINDOW_UPDATE cycles "
             "(RFC 7540 SS6.9.1's window is shared across the whole connection, not reset per "
             "stream -- many small responses should cross the replenishment threshold repeatedly)",
             len(conn_level) >= 5),
            ("every received WINDOW_UPDATE increment is positive and RFC-plausible (<= 65535)",
             all(0 < inc <= 65535 for _sid, inc in wus)),
            ("client log shows only ONE TCP connection was ever made", log.count("TCP connected to 10.0.2.2") == 1),
            ("client log shows the connection being reused, not reconnected, at least %d times "
             "(once per request after the first)" % (N_REQUESTS - 1),
             log.count("reusing open connection to 10.0.2.2") >= N_REQUESTS - 1),
            ("client log shows the LAST stream (%d) completed -- proves the dynamic table survived "
             "every insertion and eviction across all %d requests, not just the first few" %
             (expected_streams[-1] if reqs else -1, N_REQUESTS),
             ("stream %d complete" % expected_streams[-1]) in log if reqs else False),
            ("client log shows the FIRST stream (1) completed", "stream 1 complete" in log),
            ("client log shows all %d responses reached status=200" % N_REQUESTS,
             log.count("response bytes, status=200") == N_REQUESTS),
            ("client log shows more than one connection-level WINDOW_UPDATE actually sent "
             "(multiple replenishment cycles over the run, not just one)",
             log.count("WINDOW_UPDATE sent (stream 0,") >= 5),
            ("client log shows the final 200 OK line", "200 OK over Aurora TCP->TLS1.3->HTTP" in log),
            ("no error was recorded server-side", "error" not in result),
        ]

        for name, ok in checks:
            print(f"{name:100}: {'PASS' if ok else 'FAIL'}")
            if not ok: fails += 1

        if got_streams != expected_streams:
            mism = [(i, e, g) for i, (e, g) in enumerate(zip(expected_streams, got_streams)) if e != g]
            print("  stream ID mismatches (first 5):", mism[:5])
    finally:
        if srv:
            try: srv.close()
            except OSError: pass
        subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh("make user/httpsget.elf disk.img")
        shutil.rmtree(work, ignore_errors=True)
    print("\n17.5.2 HTTP/2 LONG-LIVED CONNECTION -- %d sequential requests (QEMU, real frame-level server): " % N_REQUESTS +
          ("ALL PASS" if fails == 0 else f"{fails} FAILURE(S)"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
