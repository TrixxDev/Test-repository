#!/usr/bin/env python3
"""Phase 18.5.3.1: Performance Characterization -- NOT an optimization pass.
A series of representative QEMU runs, each capturing wall-clock time plus
every counter 18.5.2 (kernel: tcp_input, tcp_tick, memcpy) and 18.5.3
(userspace: aead_seal/open, hpack_encode/decode, h2_frame) already expose,
across response size, protocol (HTTP/1.1 vs HTTP/2), connection setup cost
(cold handshake vs session resumption), and reuse (one request vs many over
the same connection) -- so the *next* optimization target is chosen from
real numbers, not a single anecdotal data point.

Reuses existing test server code directly rather than re-implementing TLS/H2
server logic a third time:
  - tools/h2_large_qemu.py's start_server() -- a real H2 server parametrized
    by (body_len, repeat), already proven at 1/5/20 MB.
  - tools/keepalive_qemu.py's start_server() -- a real HTTP/1.1-over-TLS
    keep-alive server, for the H1.1-vs-H2 comparison.
  - tools/tls_resume_qemu.py's two-path "Connection: close" pattern, for the
    cold-handshake-vs-session-resumption comparison.

This environment's from-scratch ChaCha20-Poly1305 on an emulated i686 CPU
measures roughly 1.2-1.5 KB/s (see h2_large_qemu.py's own comment) -- so the
1 MB and 5 MB scenarios alone can take 15-70+ minutes each. Run in the
background; this prints a running table as each scenario finishes so partial
results are visible without waiting for the whole sweep.

Run from the repo root: python3 tools/perf_characterize.py [scenario...]
With no arguments, runs every scenario in SCENARIOS order. Pass one or more
scenario names (see SCENARIOS below) to run a subset.
"""
import os, re, socket, sys, time, json, shutil, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import h2_large_qemu as h2l
import keepalive_qemu as ka
from qemu_serial import DEFAULT_NET_ARGS

PROD_CA_ROOTS = os.path.join(ROOT, "user/ca_roots.h")
NOW_SKEW_S = 5   # a same-wall-clock-second race between OpenSSL's cert-gen
                 # clock read and this process's own time.time() is possible
                 # in principle; costs nothing to guard against too.


def run_qemu_two_lines(cmd1, cmd2, wait1, wait2, boot_wait=7):
    """Like qemu_serial.run_qemu_serial(), but types TWO separate lines
    (cmd1, then Enter, then a wait1-second pause, then cmd2, then Enter,
    then a wait2-second pause) before shutting QEMU down.

    Needed because Aurora's shell (user/sh.c) has no `;`-separated compound
    command support at all -- typing "httpsget ... ; profstat" as ONE line
    does not run two commands, it hands "; profstat" to httpsget as two
    MORE of its OWN argv tokens. For a bodyless GET, httpsget's own
    argument loop treats every remaining non-path token as an override of
    `now` (the clock used for TLS certificate validation) -- so those two
    extra tokens silently clobber `now` down to ~0, which is always long
    before any real certificate's notBefore. That produced a very
    confusing, perfectly reproducible "leaf not yet valid" failure that
    had nothing to do with clocks, certs, or --profile at all; this
    function is the real fix, not a wider NOW_SKEW_S buffer.

    wait1/wait2 are ceilings, not fixed sleeps: draining stops as soon as
    a new "aurora> " prompt shows up (the command returned control to the
    shell) and settles briefly to catch trailing output, rather than
    always burning the whole budget -- at 1MB the real transfer took
    ~206s but a fixed-wait version would still block for the full 1000s.
    """
    PROMPT = b"aurora> "
    tmp = tempfile.mkdtemp()
    sock_path = os.path.join(tmp, "com1.sock")
    q = ["qemu-system-i386", "-kernel", "aurora.elf", "-m", "64M",
         "-drive", "file=disk.img,format=raw,if=ide", "-display", "none",
         "-chardev", "socket,id=com1,path=%s,server=on,wait=off" % sock_path,
         "-serial", "chardev:com1",
         "-no-reboot", "-no-shutdown"] + list(DEFAULT_NET_ARGS)
    p = subprocess.Popen(q, cwd=ROOT, stderr=subprocess.DEVNULL)
    buf = b""

    def drain(max_s, sock, early_exit=False):
        nonlocal buf
        baseline = buf.count(PROMPT)
        deadline = time.time() + max_s
        settle_until = None
        sock.settimeout(0.3)
        while time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                chunk = None
            else:
                if not chunk:
                    break
                buf += chunk
            if early_exit and buf.count(PROMPT) > baseline:
                if settle_until is None:
                    settle_until = time.time() + 0.4
                elif time.time() >= settle_until:
                    return

    try:
        s = None
        for _ in range(100):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock_path)
                break
            except OSError:
                time.sleep(0.1)
        if s is None:
            raise RuntimeError("QEMU never opened its serial chardev socket")
        time.sleep(boot_wait)
        drain(0.5, s)  # flush the boot banner's own prompt so it isn't
                        # mistaken for cmd1's completion below
        s.sendall(cmd1.encode() + b"\n")
        drain(wait1, s, early_exit=True)
        s.sendall(cmd2.encode() + b"\n")
        drain(wait2, s, early_exit=True)
        s.close()
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    return buf.decode(errors="replace")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def build_once(work):
    """Generate ONE test cert/root and rebuild httpsget.elf/disk.img ONCE --
    every scenario below reuses this same build; only each scenario's own
    server (a different Python process/port 443 listener) differs."""
    pem, key, der = h2l.gen_cert(work)
    h2l.write_trust_header(PROD_CA_ROOTS, der)
    if sh("make user/httpsget.elf disk.img").returncode != 0:
        raise RuntimeError("build failed")
    return pem, key


def restore_and_rebuild():
    subprocess.run(["git", "checkout", "--", "user/ca_roots.h"], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh("make user/httpsget.elf disk.img")


FIELD_RE = re.compile(r"(\w+)=(\d+)")


def parse_profile(log):
    """Pull every `[profile] name: field=N field=N ...` line into a flat
    dict, e.g. {"wall_us": 123, "aead_seal_calls": 4, "aead_seal_us": 439, ...}."""
    out = {}
    for line in log.splitlines():
        if not line.startswith("[profile]"):
            continue
        rest = line[len("[profile]"):].strip()
        name, _, fields = rest.partition(":")
        name = name.strip()
        for key, val in FIELD_RE.findall(fields):
            out[f"{name}_{key}"] = int(val)
    return out


def parse_profstat(log):
    """profstat prints bare `name=N` lines -- same idea, no "[profile]" tag."""
    out = {}
    for line in log.splitlines():
        for key, val in FIELD_RE.findall(line):
            if key in ("sched_switches", "wait_blocks", "tcp_input_calls", "tcp_input_us",
                       "tcp_tick_calls", "tcp_tick_us", "fat_read_calls", "fat_read_us",
                       "fat_write_calls", "fat_write_us", "memcpy_calls", "memcpy_bytes",
                       "tcp_read_calls", "tcp_read_iters", "tcp_read_bytes", "tcp_wait_us",
                       "tcp_connect_iters", "tcp_write_iters", "tcp_close_iters"):
                out[key] = int(val)
    return out


def start_server_retry(fn, *args, retries=15, delay=4, **kwargs):
    """Port 443 can still be held by the PREVIOUS scenario's just-closed
    listening socket for a few seconds (observed directly: a fixed 3s
    cooldown between scenarios wasn't always enough) -- retry the bind
    itself rather than guessing a cooldown long enough for every case."""
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except OSError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def run_h2(body_len, repeat, wait_s, work, cmd_paths="/a", client_repeat=None):
    """client_repeat: passed as httpsget's own --repeat N (must match the
    server's `repeat`, since both describe "how many exchanges over this one
    connection"); None means no --repeat flag (a single request)."""
    result = {}
    srv = start_server_retry(h2l.start_server, 443, os.path.join(work, "leaf.pem"),
                             os.path.join(work, "leaf.key"), result, body_len, repeat, wait_s)
    try:
        repeat_flag = f"--repeat {client_repeat} " if client_repeat else ""
        now = int(time.time()) + NOW_SKEW_S
        cmd = f"httpsget --alpn --profile {repeat_flag}10.0.2.2 {cmd_paths} {now}"
        log = run_qemu_two_lines(cmd, "profstat", wait_s, 5)
    finally:
        srv.close()
    return log, result


def run_h1(body, wait_s, work, linger=True):
    routes = {"/a": (ka.canned(body, "keep-alive" if linger else "close"), linger)}
    srv = start_server_retry(ka.start_server, 443, os.path.join(work, "leaf.pem"),
                             os.path.join(work, "leaf.key"), routes)
    try:
        now = int(time.time()) + NOW_SKEW_S
        log = run_qemu_two_lines(f"httpsget --profile 10.0.2.2 /a {now}", "profstat", wait_s, 5)
    finally:
        srv.close()
    return log


def report_row(name, log, t_wall_host, extra=None):
    metrics = parse_profile(log)
    metrics.update(parse_profstat(log))
    metrics["host_wall_s"] = round(t_wall_host, 1)
    if extra:
        metrics.update(extra)
    print(f"\n=== {name} ===")
    for k in sorted(metrics):
        print(f"  {k} = {metrics[k]}")
    ok = "200 OK" in log or "status=200" in log
    print(f"  (200 OK seen: {ok})")
    if not ok:
        print(f"  !! no 200 OK in log -- full log follows for diagnosis:")
        print("  " + log.replace("\n", "\n  "))
    return {"scenario": name, **metrics, "ok": ok}


def scenario_size(label, body_len, wait_s, work, results):
    t0 = time.time()
    log, srv_result = run_h2(body_len, 1, wait_s, work)
    responses = srv_result.get("responses", [])
    results.append(report_row(f"size:{label}", log, time.time() - t0,
                              {"body_len": body_len,
                               "data_frames": responses[0].get("data_frames_sent") if responses else None}))


def scenario_protocol_h2(label, body_len, wait_s, work, results):
    t0 = time.time()
    log2, _ = run_h2(body_len, 1, wait_s, work)
    results.append(report_row(label, log2, time.time() - t0, {"body_len": body_len}))


def scenario_protocol_h1(label, body_len, wait_s, work, results):
    body = bytes(i % 256 for i in range(body_len)).decode("latin1")
    t0 = time.time()
    log1 = run_h1(body, wait_s, work, linger=False)
    results.append(report_row(label, log1, time.time() - t0, {"body_len": body_len}))


def scenario_reuse(label, body_len, repeat, wait_s, work, results):
    t0 = time.time()
    log, srv_result = run_h2(body_len, repeat, wait_s, work,
                            client_repeat=repeat if repeat > 1 else None)
    results.append(report_row(label, log, time.time() - t0,
                              {"body_len": body_len, "repeat": repeat,
                               "responses_seen": len(srv_result.get("responses", []))}))


def scenario_resumption(work, results, wait_s=90):
    """One process, two paths on the SAME origin -- /a's response is
    Connection:close equivalent (server tears down after responding), so /b
    forces a genuinely NEW TCP connection to the same origin, at which point
    httpsget's in-process ticket cache (from /a's NewSessionTicket) attempts
    resumption -- the same pattern tools/tls_resume_qemu.py already proved.
    """
    # h2_large_qemu's server always lingers for `repeat` responses on ONE
    # connection; for a genuine reconnect we need the H1.1 keepalive server's
    # per-route linger=False instead.
    routes = {
        "/a": (ka.canned("cold-leg response", "close"), False),
        "/b": (ka.canned("resumed-leg response", "close"), False),
    }
    srv = start_server_retry(ka.start_server, 443, os.path.join(work, "leaf.pem"),
                             os.path.join(work, "leaf.key"), routes)
    try:
        now = int(time.time()) + NOW_SKEW_S
        log = run_qemu_two_lines(f"httpsget --profile 10.0.2.2 /a /b {now}", "profstat", wait_s, 5)
    finally:
        srv.close()
    results.append(report_row("resumption:combined(cold+resumed)", log, 0,
                              {"note": "both legs in one run; see log for per-leg detail"}))


SCENARIOS = ["size_1k", "size_10k", "size_100k", "protocol_h2", "protocol_h1",
             "reuse_1x", "reuse_50x", "resumption", "size_1m", "size_5m"]

RESULTS_PATH = os.path.join(ROOT, "tools", "perf_characterize_results.json")


def dump_results(results):
    """Merge into the existing results file rather than overwrite it --
    each scenario category below (protocol_h2/h1, reuse_1x/50x) MUST run as
    its own separate `python3 tools/perf_characterize.py <one scenario>`
    process, not batched into one process with others that also start a
    server on port 443: a daemon accept-loop thread (in
    h2_large_qemu.py/keepalive_qemu.py's start_server()) does not reliably
    unblock when the main thread closes its listening socket from outside
    that thread -- a well-known POSIX close()-vs-blocking-accept() race --
    so the port can stay bound for the rest of THAT process's life no
    matter how long a retry loop waits. Only exiting the whole process
    guarantees the OS releases it. Since each invocation is its own
    process, results must accumulate across runs by scenario name, not by
    in-memory list state.
    """
    existing = []
    if os.path.exists(RESULTS_PATH):
        try:
            existing = json.load(open(RESULTS_PATH))
        except (json.JSONDecodeError, OSError):
            existing = []
    new_names = {r["scenario"] for r in results}
    merged = [r for r in existing if r.get("scenario") not in new_names] + results
    with open(RESULTS_PATH, "w") as f:
        json.dump(merged, f, indent=2)
    return merged


def main():
    requested = sys.argv[1:] or SCENARIOS
    work = tempfile.mkdtemp(prefix="aurora-perfchar-")
    results = []
    try:
        build_once(work)

        if "size_1k" in requested:
            scenario_size("1KB", 1024, 40, work, results)
        if "size_10k" in requested:
            scenario_size("10KB", 10 * 1024, 45, work, results)
        if "size_100k" in requested:
            scenario_size("100KB", 100 * 1024, 150, work, results)
        if "protocol_h2" in requested:
            scenario_protocol_h2("protocol:h2(10KB)", 10 * 1024, 45, work, results)
        if "protocol_h1" in requested:
            scenario_protocol_h1("protocol:h1.1(10KB)", 10 * 1024, 45, work, results)
        if "reuse_1x" in requested:
            scenario_reuse("reuse:1x1KB", 1024, 1, 40, work, results)
        if "reuse_50x" in requested:
            scenario_reuse("reuse:50x1KB(oneconn)", 1024, 50, 200, work, results)
        if "resumption" in requested:
            scenario_resumption(work, results)
        if "size_1m" in requested:
            scenario_size("1MB", 1024 * 1024, 1000, work, results)
        if "size_5m" in requested:
            scenario_size("5MB", 5 * 1024 * 1024, 4800, work, results)
    finally:
        restore_and_rebuild()
        shutil.rmtree(work, ignore_errors=True)

    merged = dump_results(results)
    print(f"\nWrote {len(merged)} total scenario results to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
