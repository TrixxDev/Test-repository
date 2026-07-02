# AuroraOS — Security & HTTPS Foundation

With the network stack complete through a user-space HTTP client over a clean
socket API, the next foundation is **cryptography → TLS → HTTPS** — the last big
infrastructure barrier before AuroraOS can talk to the modern (HTTPS-only) web.

The discipline here is **known-answer test vectors for every primitive**, checked
in isolation on the build host so a crypto bug can never hide behind the network.
The portable primitives live in `crypto/` (freestanding C — only `<stdint.h>` /
`<stddef.h>`, no allocation, no OS calls) so the same source serves the host
test, user space, and (if ever needed) the kernel.

Run the vectors: `make crypto-test`.

## Roadmap

| Step | Piece | Verified against | Status |
|------|-------|------------------|--------|
| 1 | **SHA-256** (`crypto/sha256.c`) | NIST FIPS 180-4 | ✅ |
| 2 | **HMAC-SHA256** (`crypto/hmac_sha256.c`) | RFC 4231 | ✅ |
| 3 | **HKDF** (Extract/Expand) (`crypto/hkdf.c`) | RFC 5869 | ✅ |
| 4 | **ChaCha20** (`crypto/chacha20.c`) | RFC 8439 | ✅ |
| 5 | **Poly1305** (`crypto/poly1305.c`) | RFC 8439 + OpenSSL | ✅ |
| 5b | **ChaCha20-Poly1305 AEAD** (`crypto/chacha20poly1305.c`) | RFC 8439 §2.8.2 | ✅ |
| 6 | **TLS 1.3 record layer** (`tls/record.c`) | RFC 8446 §5 round-trip | ✅ |
| 7 | **X25519** (ECDHE key exchange) (`crypto/x25519.c`) | RFC 7748 | ✅ |
| 8 | **Transcript hash + key schedule** (`tls/transcript.c`, `tls/key_schedule.c`) | RFC 8448 §3 trace | ✅ |
| 9 | **Handshake messages v1** (`tls/handshake.c`) — ClientHello/ServerHello/Finished | RFC 8446 §4 | ✅ |
| 10 | **Client handshake FSM core** (`tls/client.c`) — event-driven, no network | RFC 8446 §4 / §A.1 | ✅ |
| 11 | **Record binding** (`tls/conn.c`) — phase gating, key switch, reassembly | RFC 8446 §5 | ✅ |
| 11b | **RFC 8448 trace runner** (`tools/tls_trace_test.c`) — engine vs real bytes | RFC 8448 §3 | ✅ |
| 12.1 | **ASN.1 DER reader** (`x509/asn1.c`) — bounds-checked TLV cursor | X.690 / RFC 8448 cert | ✅ |
| 12.2 | **X.509 certificate parser** (`x509/x509.c`) — no crypto | RFC 5280 / RFC 8448 + SAN | ✅ |
| 12.3 | **RSA verification** (`crypto/bignum.c`, `crypto/rsa.c`, `x509/verify_cert.c`) | RFC 8448 cert (self-signed) | ✅ |
| 12.4 | **Trust chain + validity + hostname** (`x509/verify_cert.c`) | synthetic CA→leaf chain | ✅ |
| 12.5 | **Certificate integration** (`tls/cert.c`) — message parse + PKI + FSM | synthetic chain via FSM | ✅ |
| 12.5b | **CertificateVerify** (`crypto/mgf1.c`, `crypto/rsa_pss.c`, `tls/cert.c`) | RFC 8448 CertificateVerify | ✅ |
| 12.6 | **FSM authentication** (`tls/client.c`) — Cert+CV+Finished, `peer_authenticated` | synthetic authed handshake | ✅ |
| 13.0a | **Network audit** (`docs/NET_SEMANTICS.md`) + **record reader** (`tls/record_reader.c`) | host framing tests | ✅ |
| 13.0b.0 | **TCP rx-buffer fix** — compacting receive ring (`net/rxring.c`), `tcp.c` migrated | host ring test (`make rxring-test`) | ✅ |
| 13.0b.1 | **Handshake driver** (`tls/driver.c`) — `transport → reader → conn → CONNECTED` | host driver test (4 chunkings + EOF) | ✅ |
| 13.0b.2a | **IP-literal connect** (`net/tcpsock.c`) — reach a numeric host without DNS | kernel build | ✅ |
| 13.0b.2b | **`tlsconnect`** (`user/tlsconnect.c`) — socket → driver → CONNECTED, embedded root | builds; QEMU run on Aurora side | ✅ code |
| 13.0b.3 | **Application-data smoke test** — send/recv one app record over the live epoch | host app-data test; QEMU echo | ✅ code |
| 13.0b.4 | **Oversized cert chain** — multi-cert, many records, buffer-limit safety | host test | ✅ |
| 13.0c | Real internet RSA endpoint: `GET /` → 200 OK | real `https://` site | later |
| 13.x.1a | **P-256 field** (`crypto/p256_field.c`) — GF(p) add/sub/mul/sqr/inv | host KAT vs Python | ✅ |
| 13.x.1b | **P-256 scalar** (`crypto/p256_scalar.c`) — GF(n), separate ring | host KAT vs Python | ✅ |
| 13.x.2 | **P-256 points** (`crypto/p256_point.c`) — Jacobian add/double/scalar-mul | host KAT: k·G, group invariants, n·G=O | ✅ |
| 13.x.2b | **EC public-key validation** (`p256_pubkey_decode`) — on-curve, bounds, n·Q=O | host: valid + invalid vectors | ✅ |
| 13.x.3 | **ECDSA verify** (`crypto/ecdsa.c`) + strict DER + fast field reduction | **484/484 Wycheproof** | ✅ |
| 13.x.4 | **X.509 ECDSA** — `prime256v1` SPKI + `ecdsa-with-SHA256` in the verify dispatcher | host KAT: cert→PASS, ±TBS→FAIL, ±sig→FAIL | ✅ |
| 13.x.5 | **TLS CertificateVerify** dispatch on SignatureScheme (0x0403) + extensible ClientHello sigalg list | host: RSA/ECDSA ✓, crossed scheme ✗ | ✅ |
| 13.x.6 | **Full ECDSA flight → CONNECTED** (no HTTP) — same FSM, no special branch | host: PASS + forged-CV/forged-Finished rejected | ✅ host |
| **14.0** | **Real Internet HTTPS** | | |
| 14.0.1 | **Intermediate CA support** — depth-N path building + basicConstraints CA:TRUE + keyUsage keyCertSign | host: depth-2 PASS; CA:FALSE/no-keyCertSign/broken-chain → FAIL | ✅ |
| 14.0.2 | **ISRG Root X1** — offline validation of a real captured LE chain (depth-3, RSA-4096) | host: 4 cases (PASS + 3 rejects) | ✅ |
| 14.0.3a | **Real Internet TLS (host)** — Aurora's engine vs a live TLS 1.3 server → CONNECTED + decrypt app record | host via egress proxy | ✅ |
| 14.0.4 | **HTTP/1.1 GET over live TLS → 200 + body** (de-chunk / Content-Length) | host: github.com 200, 240 KB | ✅ |
| 14.0.3b | **`user/httpsget.c`** — userspace HTTPS client (DNS→TCP→TLS→HTTP) over Aurora's net stack | QEMU: secure 200 (see 14.x.7) | ✅ |
| **14.x** | **ECDSA P-384 / SHA-384** (the last algorithm gap for modern ECDSA chains) | | |
| 14.x.1 | **SHA-384 / SHA-512** (`crypto/sha384.c`) — one 64-bit core, freestanding (no libgcc) | NIST FIPS 180-4 KATs | ✅ |
| 14.x.2 | **P-384 field + scalar** (`crypto/p384_field.c`, `p384_scalar.c`) — GF(p) Solinas, GF(n) | host KAT vs Python | ✅ |
| 14.x.3 | **P-384 points + ECDSA-P384-SHA384 verify** (`p384_point.c`, `ecdsa384.c`) | **504/504 Wycheproof** | ✅ |
| 14.x.4 | **X.509** — `secp384r1` SPKI + `ecdsa-with-SHA384` in the verify dispatcher | host: real P-384 chain (OK + 3 rejects) | ✅ |
| 14.x.5 | **TLS CertificateVerify** `ecdsa_secp384r1_sha384` (0x0503) + advertised in ClientHello | host: P-384 CV matrix | ✅ |
| 14.x.6 | **QEMU live-TLS diagnosis** — engine proven correct in QEMU (200 OK); failures were cert-policy, now surfaced (`cert_reason`) | QEMU: 200 (validation off), reliable | ✅ |
| 14.x.7 | **Secure HTTPS 200 OK in QEMU** — validation ON, depth-N Root→Inter→Leaf, RSA + P-256 + P-384 | `tools/securehttps_qemu.py`: 3/3 PASS | ✅ |
| 14.0.5 | Expand the trust store toward a browser bundle | superseded by 15.1 | — |
| **15.0** | **Memory reduction** — DER-slice fields, `TLS_MAX_CHAIN` 4→6, buffer sizing analysis | host | ✅ |
| 15.0.1 | `x509_cert.san_dns[8][256]` → `x509_slice` views into the DER (no copy) | host | ✅ |
| 15.0.2 | `issuer_cn`/`subject_cn` → `x509_slice`; `sizeof(x509_cert)` 2408 B → 184 B (−92%) | host: DER-lifetime invariant test | ✅ |
| 15.0.3 | `TLS_MAX_CHAIN` 4 → 6 (cheap now that each slot is ~184 B) | host | ✅ |
| 15.0.4 | `tls_conn.hs_buf` / record-reader buffer analysis — confirmed correctly sized, documented not shrunk; `httpsget` response buffer 32 KiB → 8 KiB | host + QEMU | ✅ |
| **15.1** | **Trust store expansion** — 3 ECDSA P-384 roots (ISRG Root X2, GTS Root R3/R4) alongside the 5 RSA roots | host: parse + self-signature verify; QEMU: 8-root smoke + 14.x.7 regression | ✅ |
| **15.2** | **HTTP redirects** — `user/url.c` (RFC 3986 §5.3 reference resolution) + a per-hop full pipeline restart in `httpsget` (301/302/303/307/308, ≤20 hops, loop guard, scheme/host/port changes) | `make url-test` (31 cases); `tools/redirects_qemu.py`: 3/3 PASS; 14.x.7 regression still 3/3 | ✅ |
| **15.3** | **DHCP** — `net/dhcp.c` (DISCOVER→OFFER→REQUEST→ACK, T1/T2 renewal) + `net/netcfg.c` (`struct net_config` — the single live IP/mask/gateway/DNS, replacing the scattered `IP_LOCAL`/`IP_GATEWAY`/`IP_DNS` compile-time constants) | `make dhcp-test` (47 cases); `tools/dhcp_qemu.py`: 3/3 PASS (default subnet matches static fallback byte-for-byte, a different subnet is correctly adopted and ARP/ICMP-usable, `nodhcp` opts out); 14.x.7 + 15.2 regressions still 3/3 + 3/3 | ✅ |
| **15.4** | **HTTP keep-alive** — `httpsget` reuses an open TCP+TLS session across same-origin requests (multi-path CLI + same-origin redirects) when the response says so and has a determinate, bounded length; optimistic reuse with a one-shot reconnect if the kept connection was already dead | `tools/keepalive_qemu.py`: 3/3 PASS (3-path reuse, `Connection: close` forces a fresh handshake, a stale reused connection recovers); 14.x.7 + 15.2 + 15.3 regressions still 3/3 + 3/3 + 3/3 | ✅ |
| **15.5** | **Trust store: a first real approximation of a browser bundle** — 8 → 21 roots across 9 issuer organizations (Let's Encrypt, DigiCert, Sectigo, Google, GlobalSign, Amazon, Microsoft, Entrust), generated from `tools/trust_roots/*.pem` by `tools/gen_ca_roots.py` instead of hand-edited | `make ca-roots-test` (parse + coverage floor + a real GTS Root R1 → GTS CA 1C3 signature check on CA-published DER); QEMU: 21/21 parse with no failure; 14.x.7 + 15.2 + 15.3 + 15.4 regressions still 3/3 + 3/3 + 3/3 + 3/3 | ✅ |
| **15.6** | **DNS cache** — positive (TTL-bounded, clamped) and negative (fixed 10 s) caching in `net/dns.c`, transparent to every existing caller (`tcpsock_connect`, `net_http_get`, `net_selftest`); a cached lookup returns immediately with no network round trip | `make dns-cache-test` (27 cases: name equality, TTL clamping, find/allocate/evict/expire); `tools/dns_cache_qemu.py`: 2/2 PASS against the real SLIRP-forwarded resolver (a repeat query hits the cache; an unresolvable name is negative-cached); 14.x.7 + 15.2 + 15.3 + 15.4 regressions still 3/3 each | ✅ |
| **15.7** | **TLS 1.3 session resumption** (RFC 8446 §2.2/§4.2.11/§4.6.1) — a cached `NewSessionTicket` (PSK + lifetime, keyed by host:port in `httpsget`) offers `pre_shared_key`/`psk_key_exchange_modes` on the next connection to the same origin; a server-accepted PSK skips Certificate/CertificateVerify entirely, with a transparent fallback to a full handshake if the server doesn't select it | `make tls-trace-test` (RFC 8448 §4 PSK/binder/resumption-secret vectors byte-exact, plus a synthetic FSM-level abbreviated-handshake test); `tools/tls_resume_qemu.py` against a real OpenSSL-backed TLS 1.3 server: 1st connection full handshake + ticket cached, 2nd connection resumed — confirmed both client-side (trace) and server-side (`SSL_session_reused`); 14.x.7 + 15.2 + 15.3 + 15.4 regressions unaffected | ✅ |
| **15.10** | **gzip / DEFLATE decompression** (RFC 1951 + RFC 1952) — a from-scratch, genuinely incremental inflate (`compress/inflate.c`: bit reader, stored/fixed/dynamic Huffman, 32 KiB sliding window) wrapped in a gzip container (`compress/gzip.c`: header/trailer, CRC32/ISIZE verification); `httpsget` sends `Accept-Encoding: gzip` and decompresses a `Content-Encoding: gzip` response as wire bytes arrive, not after buffering the whole compressed body | `make crc32-test` + `make inflate-test` (real raw-deflate streams incl. a 32 KiB+ window wraparound, plus a tiny-chunk/tiny-output-buffer streaming test) + `make gzip-test` (real gzip streams incl. FLG.FNAME, CRC32/ISIZE tamper rejection); `tools/gzip_qemu.py` against a real TLS 1.3 server: the server sees the real `Accept-Encoding: gzip` request header and answers with genuine gzip-compressed bytes, which `httpsget` decompresses to the original readable text inside QEMU; 14.x.7 + 15.2 + 15.3 + 15.4 + 15.7 regressions unaffected | ✅ |
| **15.9** | **Cookie jar** (RFC 6265) — a compact, fixed-size (`user/cookiejar.c`, 32 entries, LRU eviction) process-lifetime jar: Domain/Path scoping, Max-Age/Expires (Max-Age wins when both are present), Secure/HttpOnly, deletion via a past/zero expiry, and rejecting a Domain attribute for a host that doesn't control it. `httpsget` parses every `Set-Cookie` on a response and sends a scoped `Cookie:` header on every request | `make cookiejar-test` (30 cases: domain/path matching incl. the no-slash-boundary negative case, Max-Age-vs-Expires precedence, deletion, overwrite-on-same-identity, LRU eviction, Secure/host-only enforcement, unrelated-domain rejection); `tools/cookies_qemu.py` against a real TLS 1.3 server: a session cookie set on one request comes back correctly on later requests in the same run, and a `Path=/admin`-scoped cookie is confirmed both withheld outside its path and included inside it — real RFC 6265 scoping, not "send everything ever seen"; 14.x.7 + 15.2 + 15.3 + 15.4 + 15.7 + 15.10 regressions unaffected | ✅ |
| **15.8** | **Multi-origin session cache** — the single global TLS connection/reader/ticket-cache is replaced by `TLS_SESSION_SLOTS` (4) origin-keyed slots, each able to hold a live, reusable connection *and* a session ticket independently and simultaneously; a redirect to a different origin no longer closes the origin it left, so a later hop back to it can reuse the still-open connection (zero handshake) or, failing that, its ticket (PSK resumption) — no threads, timers, or queues, exactly as synchronous as every phase before it | `tools/session_cache_qemu.py` against two real TLS 1.3 servers on different ports of the same host (two distinct origins): a redirect chain A → B → A shows exactly one TCP connection to each of A and B, and the return to A is served by reusing its still-open connection with zero further TLS activity; full existing host + QEMU regression suite (incl. 15.7 resumption, whose ticket now lives inside the same slot) unaffected | ✅ |
| **16.1** | **HTTP POST** (opening the "Web Platform" series, `16.x`, distinct from the `15.x` HTTPS v2 milestone) — `httpsget --post <host> <path> <body>` sends `body` as `application/x-www-form-urlencoded` with an auto-computed `Content-Length`; a redirect after a POST downgrades to a bodyless GET on the next hop (legacy 301/302/303 behavior; RFC 7231's method-and-body-preserving 307/308 explicitly not yet implemented) | `tools/post_qemu.py` against a real TLS 1.3 server: the server inspects the *actual* incoming request (not just httpsget's own log) and confirms method, `Content-Type`, `Content-Length` and the exact body bytes, then confirms the following redirect hop arrives as a bodyless GET; full existing host + QEMU regression suite unaffected | ✅ |
| **16.2** | **HTTP authentication (Basic + Bearer)** — `httpsget --auth-basic user:pass` / `--auth-bearer token` send `Authorization: Basic <base64>` / `Authorization: Bearer <token>` (`user/base64.c`, a new RFC 4648 encoder — nothing else in the codebase needed one yet); the header is re-scoped on every redirect hop to whichever origin it was given for, so it naturally follows a same-origin redirect and just as naturally stops the moment a redirect leaves that origin | `make base64-test` (RFC 4648 §10's own vectors + realistic `user:pass` strings + an undersized-buffer rejection check); `tools/auth_qemu.py` against real TLS 1.3 servers: the server decodes the Basic header itself (not trusting httpsget's encoder) and confirms the exact credentials, confirms the exact Bearer token, and confirms a Bearer token given for origin A is *not* sent to origin B after a cross-origin redirect; full existing host + QEMU regression suite unaffected | ✅ |
| **16.3** | **RFC-correct redirects for a request with a body** — 16.1's per-hop method/body decision is now made fresh after every redirect response instead of being fixed at the first hop: `307`/`308` resend the exact method and body (RFC 7231 §6.4.7 / RFC 7238), while `301`/`302`/`303` still downgrade to a bodyless `GET` | `tools/redirect_preserve_qemu.py` against a real TLS 1.3 server: a real 4-hop chain (`POST` →307→ `POST` →308→ `POST` →302→ `GET`) confirms both preserving hops resend the identical body bytes and the final `302` hop downgrades to a bodyless `GET` even though the request had been carried as `POST` through the two hops before it — proving the decision is made per-redirect, not "sticky" for the rest of the chain; full existing host + QEMU regression suite (incl. 16.1's own 302-downgrade test) unaffected | ✅ |
| **16.4** | **multipart/form-data** — `httpsget --post-multipart <host> <path> <field=value \| field=@localfile> [...]` encodes each field as its own MIME part behind a generated boundary; `build_request()`'s Content-Type is now caller-supplied (`content_type`, threaded alongside `body`/`bodylen` through `fetch_request()`/`fetch()`/`fetch_one()`, and preserved or dropped on a redirect by the same 307/308-vs-everything-else rule 16.3 already applies to the body) instead of a hardcoded url-encoded string; a `field=@localfile` value is read off Aurora's own FAT32 disk (`open()`/`read()` in a loop — there's no `stat`/`lseek` to size a file up front) and sent as a file part with a fixed `application/octet-stream` Content-Type | `tools/multipart_qemu.py` against a real TLS 1.3 server: the server extracts the boundary from the *actual* Content-Type header and parses the *actual* body itself into parts (not trusting httpsget's own log), confirming a text field's exact value, a file field's filename/Content-Type, and that the file part's bytes match a real on-disk file byte-for-byte; a same-origin 307 hop then confirms the Content-Type (boundary included) and raw body are byte-identical on the retry, proving 16.3's preservation rule now correctly covers a multipart Content-Type too; full existing host + QEMU regression suite unaffected | ✅ |
| **16.5** | **General `--method`** — `httpsget --method <GET\|HEAD\|OPTIONS\|DELETE\|POST\|PUT\|PATCH> ...` replaces the old hardcoded GET-or-POST choice with a validated table (`--post` is now just `--method POST`'s older, still-supported spelling); PUT/PATCH reuse `--post`'s body-shaped argument parsing, HEAD/OPTIONS/DELETE reuse GET's multi-path bodyless parsing — `build_request()`/`fetch_request()`/`fetch()`/`fetch_one()` needed no changes at all, since they already took `method` as a plain string. Fixes a real hang risk surfaced by adding HEAD: RFC 7230 §3.3.3 says a HEAD response body is *always* empty regardless of its `Content-Length` (which, if present, describes what a GET would have returned) — without a fix, a keep-alive HEAD response advertising a nonzero `Content-Length` would make the read loop wait forever for body bytes the server will never send; `resp_feed()`/`reusable()` now both special-case a HEAD request's response framing | `tools/method_qemu.py` against a real TLS 1.3 server: confirms `--method PUT`'s real method and exact body bytes, `--method DELETE`'s real method and bodyless request, and — the critical case — that `--method HEAD` against a server advertising `Content-Length: 999999` on a keep-alive connection that sends *zero* actual body bytes still reaches `status=200` within the ordinary wait budget instead of hanging; full existing host + QEMU regression suite (incl. 16.1/16.2/16.3/16.4's own POST/PUT-adjacent paths) unaffected | ✅ |
| **17.0** | **ALPN** (RFC 7301, opening the "modern transport" series, `17.x`, that follows the now-closed `16.x` Web Platform series) — `httpsget --alpn` offers `["h2", "http/1.1"]` in the TLS ClientHello (opt-in: omitted entirely, byte-identical to every pre-17.0 ClientHello, unless the flag is given) and a new `tls_parse_encrypted_extensions()` extracts the server's selection (best-effort/non-fatal on a parse quirk — unlike Certificate/CertificateVerify, nothing here is security-critical enough to abort a handshake over). This phase is deliberately *just* the negotiation: there is no HTTP/2 framing yet, so if the server actually selects `h2`, `fetch_begin()` refuses to continue that connection rather than sending an HTTP/1.1 request line a peer now expecting HTTP/2 framing would never understand | `make tls-test` (21 new cases: a no-ALPN ClientHello is unaffected, an ALPN ClientHello carries both offered names and is exactly the expected 18 bytes longer, ALPN correctly precedes `pre_shared_key` when both are offered together, and `tls_parse_encrypted_extensions()` extracts `h2`/`http/1.1` selections, tolerates an unrelated extension alongside ALPN, and rejects (without over-reading) a malformed message); `tools/alpn_qemu.py` against a real TLS 1.3 server with an independent OpenSSL-backed ALPN implementation: a server that can only pick `http/1.1` does, and Aurora proceeds normally; a server that prefers `h2` gets it, and Aurora's own log shows the refusal while the server independently confirms *no bytes at all* arrive after the handshake; `--alpn` omitted against a server supporting both proves no extension was sent. Full existing host suite and a 12-script QEMU regression sweep (incl. 15.7 PSK resumption, since `EncryptedExtensions` parsing is now always-on for every connection, ALPN or not) all pass unaffected | ✅ |
| **17.1.1** | **HTTP/2 connection-establishment handshake** (RFC 7540 §3.5/§6.5, new `http2/` directory: `frame.c` — the 9-byte frame header, RFC 7540 §4.1 — and `settings.c` — building an empty SETTINGS and a SETTINGS ACK, RFC 7540 §6.5) — once ALPN (17.0) actually selects `h2`, `h2_handshake()` sends the 24-byte connection preface and an empty SETTINGS frame, then reads frames (across as many TLS records/raw reads as it takes, reassembling a frame header that lands split across two of them) until both the server's own SETTINGS (acknowledged immediately, as §6.5 requires) and a SETTINGS ACK for Aurora's own have arrived — their relative order isn't guaranteed by the spec, so both are watched for independently. Anything else seen in between (a connection-level `WINDOW_UPDATE` right after SETTINGS is common in real servers) is skipped, not rejected — the same "tolerate what you're not specifically waiting for" posture 17.0 established for `EncryptedExtensions`; a `GOAWAY` ends the attempt immediately, since nothing being waited for is ever coming after that. Still `17.1.1`'s entire scope: there is no HEADERS/DATA framing yet, so even a *successful* handshake still can't carry a request — `fetch_begin()` still ends the connection attempt either way, just backed now by a genuinely negotiated h2 connection instead of an outright ALPN-result refusal | `make h2-test` (22 new cases: frame-header encode/decode round-trips incl. 24-bit length and 31-bit stream-ID boundary values, a known byte-for-byte encoding, the reserved top bit surviving a hostile peer setting it, capacity/range rejection, and the SETTINGS/SETTINGS-ACK builders' exact wire bytes); `tools/h2_handshake_qemu.py` against a *real frame-level* HTTP/2 test server (a from-scratch second Python implementation, not a copy of `http2/frame.c` — a bug shared between both wouldn't hide behind agreement): confirms the exact 24-byte preface arrives, the client's SETTINGS is real and empty, a deliberately non-empty server SETTINGS *plus* an interleaved `WINDOW_UPDATE` are both handled correctly (proving the skip logic tolerates an unknown frame type mid-handshake, not just extra bytes of a known one), both SETTINGS ACKs are exchanged in both directions, and — the whole point of this phase's scope boundary — nothing at all is sent afterward. All 13 checks pass; `tools/alpn_qemu.py`'s own h2-selected scenario is updated to match (Aurora now genuinely attempts the handshake instead of refusing outright, so its assertions moved from "no bytes ever arrive" to "the real preface arrives, and no fetch ever completes either way"). Full existing host suite and the same 12-script QEMU regression sweep as 17.0 all pass unaffected | ✅ |
| **17.1.2** | **DATA frame + generic frame reader** — a new `h2_frame_reader` (`http2/frame.c`) replaces `h2_handshake()`'s ad-hoc header-accumulator/skip-bytes logic with a real, reusable, payload-*preserving* reader (the same role `tls_record_reader` plays for TLS records one layer up): `feed()` takes arbitrarily-chunked plaintext and returns how many bytes it actually consumed (bounded-memory — one frame, up to the RFC 7540 §6.5.2 default `SETTINGS_MAX_FRAME_SIZE`, at a time — not an unbounded queue), `next()` drains a completed frame's header *and* payload bytes. A new `http2/data.c` decodes a DATA frame's payload (RFC 7540 §6.1), including the padding case (`Pad Length` byte + data + padding, rejecting padding ≥ the whole payload) and builds one for future use. `h2_handshake()` itself now recognizes a DATA frame by name in its log (still doesn't act on it — no stream is open) rather than silently skipping it as an unknown type | `make h2-test` (23 new cases: a whole frame fed in one call vs. byte-at-a-time vs. split mid-*payload* all reassemble identically, two complete frames delivered in one `feed()` call drain correctly via two `next()` calls, an oversized frame declaration is rejected before any payload is buffered; DATA parse/build covering unpadded, padded, the two rejection cases, and an END_STREAM round-trip); `tools/h2_handshake_qemu.py` extended with a real, hand-rolled-in-Python, *padded*, `END_STREAM`-flagged DATA frame sent on a stream nothing ever opened, interleaved between the server's SETTINGS and its SETTINGS ACK — Aurora's log names it correctly ("DATA frame seen") without disrupting the handshake's completion, proving the generic reader handles a genuine payload-bearing frame mid-exchange, not just extra bytes of an already-known type. All 14 checks pass (up from 13). Because `h2_handshake()` was refactored, not just extended, this phase repeats the full previous regression sweep (13 QEMU scripts incl. `alpn_qemu.py`) end to end to confirm byte-identical externally-observable behavior — all pass unaffected | ✅ |

With X25519 done the **cryptographic** toolbox for a TLS 1.3 ChaCha20-Poly1305
client is complete — hash, MAC, HKDF, AEAD, record layer, and now key agreement.
What is left is pure protocol: the key schedule glue, the handshake state
machine, and certificate/signature verification (a later, separable layer).

With AEAD done, the **symmetric** half of TLS 1.3 is essentially complete: hash,
MAC, key schedule (HKDF), stream cipher and authenticated encryption are all
RFC-verified. What remains is protocol logic (record framing, key schedule glue,
handshake state machine) plus the asymmetric pieces (X25519, then certificate /
signature verification) — a separate `tls/` layer over these primitives.

The PKI layer is now under way in `x509/` (ASN.1 DER reader done; X.509 parse,
RSA verification and a minimal trust store to follow). Deliberately still **out of
scope**: ECDSA (added after RSA, since the RFC 8448 reference cert is RSA), full
certificate-chain path building, OCSP/CRL revocation, AIA fetching, name
constraints, and wildcard corner cases — a later hardening pass.

### Planned layering

`crypto/` stays pure primitives, independent of TLS and verifiable on the host.
The protocol lands later in a separate `tls/` tree so TLS-specific glue never
leaks into the primitives:

```
crypto/  sha256  hmac  hkdf  chacha20  poly1305      (RFC-vector tested, no TLS)
   ↓
tls/     hkdf_label  transcript  record  handshake    (TLS protocol)
```

In particular `HKDF-Expand-Label` / `Derive-Secret` are TLS helpers (`tls/`), not
crypto primitives — they wrap `hkdf_expand`, they don't live inside it.

`tls/` has its own host harness: `make tls-test`.

## Step 1–2 — SHA-256 + HMAC-SHA256

`sha256_init/update/final` (+ a one-shot `sha256()`) implement FIPS 180-4;
`hmac_sha256()` is RFC 2104 over it. `make crypto-test` runs:

```
SHA-256 (NIST FIPS 180-4):   "" / "abc" / 56-byte / 1,000,000 x 'a'   -> PASS
HMAC-SHA256 (RFC 4231):      cases 1, 2, 3, 4, 6 (long key)           -> PASS
CRYPTO TEST: ALL PASS
```

HMAC-SHA256 is the workhorse the next steps build on: HKDF (TLS 1.3's entire key
schedule), Poly1305 keying, and token/signature checks.

## Step 3 — HKDF (RFC 5869)

`hkdf_extract(salt, ikm) -> prk` is just `HMAC-SHA256(salt, ikm)` (a zero salt of
`HashLen` bytes when none is given); `hkdf_expand(prk, info, len) -> okm` is the
`T(i) = HMAC(prk, T(i-1) | info | i)` counter loop, truncated to `len`. Both are
freestanding (a single fixed `T(i-1) | info | i` buffer, no allocation). `make
crypto-test` runs all three RFC 5869 SHA-256 vectors (PRK **and** OKM):

```
HKDF-SHA256 (RFC 5869):  case 1 (salt+info) / case 2 (80-byte inputs, 82-byte OKM)
                         / case 3 (no salt, no info)   -> PASS
```

This is the pivot point for TLS 1.3: its key schedule is `HKDF-Extract` plus
`Derive-Secret`/`HKDF-Expand-Label`, both thin wrappers over these two calls, so
the handshake's secret derivation becomes mechanical once the AEAD is in place.

## Step 4 — ChaCha20 (RFC 8439)

ChaCha20 comes before AES on purpose: on i686 there is no AES-NI, ChaCha20 is
simpler and constant-time by construction, and it pairs with Poly1305 into
`TLS_CHACHA20_POLY1305_SHA256` — a complete HTTPS path with no AES at all. The
module is a small three-call API (`chacha20_init` / `chacha20_block` /
`chacha20_xor`), with the quarter-round exposed so the lowest layer is testable
on its own. `make crypto-test` checks all three RFC 8439 levels:

```
ChaCha20 (RFC 8439):  quarter-round (§2.1.1) / state quarter-round (§2.2.1)
                      / 64-byte block keystream (§2.3.2)
                      / 114-byte encryption (§2.4.2)   -> PASS
```

A bug at any level invalidates everything above it, so the quarter-round is
proven first, then the block function, then real XOR encryption end-to-end.

## Step 5 — Poly1305 (RFC 8439)

A pure one-time authenticator: `poly1305_auth(tag, msg, len, key)` — message plus
a one-time 32-byte key → a 16-byte tag, nothing TLS-specific. Arithmetic is mod
2^130-5 in five 26-bit limbs (the "donna-32" representation), so it needs only
32×32→64-bit multiplies and no 128-bit type — fine for plain i686.

Block boundaries are where Poly1305 implementations usually break, so beyond the
canonical RFC §2.5.2 vector the harness checks lengths 0, 1, 15, 16, 17. Those
expected tags come from an **independent** reference (OpenSSL 3's
`openssl mac POLY1305`), not from this code, so they are real known-answer tests:

```
Poly1305 (RFC 8439):  RFC 2.5.2 (34-byte)
                      len 0 / 1 / 15 / 16 / 17  (vs OpenSSL)   -> PASS
```

`len 0` lands on `tag == s == key[16..31]`, confirming the empty-message path.

> **One-time key:** Poly1305 is only secure if each key authenticates exactly one
> message. The AEAD step derives a fresh Poly1305 key per record from ChaCha20.

## Step 5b — ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)

The combined construction TLS 1.3 actually uses (`TLS_CHACHA20_POLY1305_SHA256`):

- `seal(key, nonce, aad, pt) -> ct, tag` — derive a one-time Poly1305 key from
  the ChaCha20 keystream at counter 0 (§2.6), encrypt with counter 1, then MAC
  `aad | pad16 | ct | pad16 | le64(aadlen) | le64(ctlen)`.
- `open(...)` — recompute the tag, compare it in **constant time**, and only then
  decrypt. A bad tag returns `-1` and yields no plaintext.

To MAC several non-contiguous spans without a big buffer (TLS records reach
~16 KB), Poly1305 grew a streaming `init`/`update`/`final` context; the one-shot
`poly1305_auth` is now a thin wrapper, so its KATs are unchanged.

Beyond matching the §2.8.2 vector, the harness checks the security property the
whole TLS record layer rests on — that authentication actually rejects tampering:

```
ChaCha20-Poly1305 AEAD:  seal ct / tag (§2.8.2)   -> match
                         open(valid) -> 0, recovers plaintext
                         flip 1 byte of ciphertext / AAD / tag -> open == -1
```

## Project maturity snapshot (at this milestone)

A rough self-assessment after the AEAD step — the symmetric crypto is no longer
the weak point; TLS/HTTPS now is:

| Subsystem | Maturity |
|-----------|----------|
| Kernel (VM, IPC, SHM, timers) | █████████░ |
| Window manager / compositor | █████████░ |
| Desktop UX (Dock/Finder/Viewer/Settings) | ████████░░ |
| Filesystem | ███████▌░░ |
| Networking (L2–L4, DNS, sockets) | ████████▌░ |
| TCP (retransmit; no RTT est. yet) | ███████▌░░ |
| Crypto — symmetric primitives | █████████░ |
| TLS 1.3 client (handshake + record binding, RFC 8448-verified; no cert trust) | ████████░░ |
| Certificate / X.509 PKI | ░░░░░░░░░░ |
| GPU acceleration | █░░░░░░░░░ |
| x86_64 port | ░░░░░░░░░░ |

The first real internet request from Aurora Fetch hit `426 Upgrade Required` —
the web itself telling Aurora to learn HTTPS. That makes the TLS record layer the
single highest-value next step, which is exactly what step 6 begins.

## Step 6 — TLS 1.3 record layer (RFC 8446 §5)

The crossover from `crypto/` to `tls/`: the first protocol code, pure framing
over the verified AEAD, no networking (bytes in, bytes out).

- `tls_record_seal(type, plaintext) -> TLSCiphertext` builds `TLSInnerPlaintext`
  (`content || real_type`), derives the nonce, and AEAD-seals in place. The
  on-wire `opaque_type` is always `application_data` (23); the real type is
  hidden inside the encryption.
- `tls_record_open(record) -> (type, content)` reconstructs the nonce from its
  own sequence counter, AEAD-opens (verify-before-decrypt), then strips the
  trailing zero padding and the inner type byte.
- **nonce** = `write_iv XOR left-pad(seq, 12)` (§5.3); **AAD** = the 5-byte
  record header (§5.2). The sequence number is implicit state on each side, so a
  reordered or replayed record derives the wrong nonce and fails authentication.

TLS 1.3 publishes no ChaCha20-Poly1305 record KAT, so `make tls-test` pins it
three ways:

```
nonce (§5.3):     iv/seq combinations vs hand-computed values
framing:          record == the verified AEAD invoked manually, byte-for-byte
behaviour:        round-trip recovers (type, content); seq advances; identical
                  plaintext at seq 0 vs 1 differs on the wire; tampered byte ->
                  open == -1; wrong sequence number -> open == -1
```

This is the bridge to the handshake: ServerHello-onward is just records, and
`EncryptedExtensions` / `Finished` are sealed/opened with exactly this code.

## Step 7 — X25519 (RFC 7748)

The last fundamental primitive — Diffie-Hellman on Curve25519. The shared secret
it produces is the input to the TLS 1.3 key schedule (`HKDF-Extract(.., ECDHE)`).

A constant-time Montgomery ladder with branch-free conditional swaps, so the
secret scalar never steers control flow or memory access. Field arithmetic is mod
2^255-19 in 16 limbs of radix 2^16 — 64-bit multiplies only, no 128-bit type,
fine for plain i686. `make crypto-test`:

```
X25519 (RFC 7748):  scalarmult vectors 1 & 2 (§5.2) / iterative 1-iter (§5.2)
                    / §6.1 Diffie-Hellman: Alice & Bob publics, shared secret,
                      and both sides agree   -> PASS
```

The §6.1 case is the real end-to-end check: derive each side's public key from
its secret, then confirm `X25519(a, B) == X25519(b, A)` == the RFC's shared
secret — exactly the exchange the handshake will run.

## Cryptographic toolbox: complete

```
crypto/   sha256  hmac  hkdf  chacha20  poly1305  chacha20poly1305  x25519
tls/      record
```

Every box a TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` client needs for its maths is
now present and RFC-verified. The remaining work is protocol state, not crypto:
key schedule (transcript hash + HKDF-Expand-Label), the handshake messages
(ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify
→ Finished), and certificate/signature validation.

## Step 8 — transcript hash + key schedule (RFC 8446 §7.1)

The deterministic key algebra that turns the ECDHE secret + handshake transcript
into traffic secrets and AEAD keys — pure protocol over the verified primitives.

- `tls/transcript.c`: a running SHA-256 over the handshake messages, with a
  **non-destructive snapshot** (`tls_transcript_hash` copies the context before
  finalizing) because the handshake needs the hash at several points while still
  appending later messages.
- `tls/key_schedule.c`: `tls_hkdf_expand_label` / `tls_derive_secret` (TLS
  helpers over `hkdf_expand`, exactly as the layering note requires — not crypto
  primitives), and `tls_key_schedule_derive` building Early → Handshake → Master
  secrets and the client/server handshake-traffic secrets.

Verified against the **RFC 8448** "Simple 1-RTT Handshake" trace. The schedule
depends only on SHA-256 and the ECDHE secret (not the AEAD), so that trace is an
authoritative reference even though it negotiates AES-128-GCM:

```
key schedule (RFC 8448 §3):  ECDHE secret (derived by our own X25519 from the
                             trace's client priv + server pub)
                             -> early / handshake / master secret
                             -> client & server handshake-traffic secret
                             -> server write key+iv via HKDF-Expand-Label   -> match
```

The chain is end-to-end: our X25519 produces the shared secret, which flows
through the whole schedule to byte-exact agreement with the RFC. What is left is
sequencing — feeding real ClientHello/ServerHello bytes through this code in a
handshake state machine — plus certificate/signature validation.

## Step 9 — handshake messages v1 (RFC 8446 §4)

The deterministic message core, no certificates yet: build ClientHello, parse
ServerHello, and the Finished verify_data. Only the extensions 1-RTT ECDHE needs
(key_share, supported_versions, supported_groups, signature_algorithms, SNI).

- `tls_build_client_hello` serializes a real ClientHello (length-back-patched
  writer) offering `TLS_CHACHA20_POLY1305_SHA256` + an x25519 key_share.
- `tls_parse_server_hello` is bounds-checked, walks the extensions, and pulls out
  the negotiated cipher suite and the server's x25519 key_share.
- `tls_finished_key` / `tls_finished_verify_data` / `tls_check_finished` — the
  Finished danger zone, kept tiny: `finished_key = HKDF-Expand-Label(secret,
  "finished", "", 32)` and `verify_data = HMAC(finished_key, transcript_hash)`,
  checked in constant time. HKDF-Expand-Label is already pinned to RFC 8448 for
  the `key`/`iv` labels, so `finished` is correct by the same code path.

The headline test is a full **loopback handshake** — no hardcoded server, no
network:

```
handshake (loopback):  client builds ClientHello, server builds ServerHello
                       -> ServerHello parses, cipher + key_share extracted
                       -> X25519 agrees on both sides
                       -> client & server derive identical handshake-traffic
                          secrets from transcript(CH||SH)
                       -> Finished verifies; one flipped byte is rejected
```

This is the proof the whole pipeline composes: two independent peers exchange
real handshake bytes and converge on the same keys. What remains is driving it as
an event-driven state machine over the record layer, then certificate trust.

## Step 10 — client handshake FSM core (RFC 8446 §4 / §A.1)

A deterministic, event-driven engine over *plaintext* handshake messages. It owns
the transcript, the key schedule, and a **(state, key_phase) pair kept
deliberately separate** — `state` is which message is expected next, `phase`
(EARLY → HANDSHAKE → APPLICATION) is which traffic keys the record layer should
use. No network, no record layer, no certificate validation (v1); the ephemeral
key and client random are injected, so a given event sequence always replays to
the same bytes.

Three invariants are enforced exactly where TLS implementations usually drift:

- **transcript phasing.** ServerHello is added before deriving the handshake
  secrets (so they bind `Transcript(CH..SH)`); the server Finished is verified
  over `Transcript(CH..CertificateVerify)` *before* it is appended; the client
  Finished and the application secrets are computed over `Transcript(CH..server
  Finished)`. One message out of place and the secrets diverge.
- **key-phase anchors.** Phase flips to HANDSHAKE only at ServerHello and to
  APPLICATION only at the server Finished — never ad hoc.
- **handshake-only progress.** The FSM consumes handshake messages; record/AEAD
  failures are the caller's concern and never advance it.

Verified by a full **deterministic loopback handshake** through the FSM — a test
"server" emits ServerHello + (dummy) EncryptedExtensions/Certificate/
CertificateVerify + a correctly-keyed Finished, and:

```
FSM loopback:  START -> WAIT_SH -> WAIT_EE -> WAIT_CERT -> WAIT_CV
               -> WAIT_FINISHED -> CONNECTED, phase EARLY -> HANDSHAKE -> APPLICATION
   FSM and server agree on the handshake- and application-traffic secrets
   server-side check of the client's emitted Finished passes
   tampered server Finished -> -1 and the FSM enters ERROR
   out-of-order message (EE while WAIT_SH) -> -1
```

Next is binding this to `tls_record_seal/open` (plaintext gating, key switch on
each phase anchor, per-phase sequence numbers), then certificate trust.

## Step 11 — record binding (RFC 8446 §5)

`tls/conn.c` is the layer between raw TLS records and the FSM — the point where
the handshake finally rides the encrypted record layer. It does three things and
nothing else:

- **Plaintext-vs-encrypted gating.** ClientHello and ServerHello are plaintext
  handshake records; everything after ServerHello is an `application_data` record
  opened with the current read keys. The conn decides which based on the FSM's key
  phase, not the record layer.
- **Key switching at the two phase anchors.** ServerHello installs the handshake
  traffic keys; the server Finished installs the application traffic keys. Each
  switch builds a *fresh* record epoch, so its sequence number restarts at 0 — TLS
  1.3 treats a key change as a new encryption epoch (§5.3). The client Finished is
  sealed under the handshake epoch *before* the switch to application keys.
- **Handshake reassembly.** One record may coalesce the whole server flight
  (EncryptedExtensions | Certificate | CertificateVerify | Finished) or split a
  single message across records; the conn buffers bytes and hands the FSM exactly
  one complete message at a time.

The dependency direction is one-way — `conn → { FSM, record layer } → crypto` —
so the record layer never inspects handshake state and the FSM never sees a
record. A direct consequence, and the headline invariant, is that the two failure
modes are reported distinctly: a record-layer (AEAD) failure is a transport error
that leaves the FSM intact, while only a real protocol violation drives it to
ERROR. `make tls-test` proves the whole thing without a socket:

```
record binding:  ClientHello emitted as a plaintext record
                 plaintext ServerHello -> handshake epoch (rx/tx seq reset to 0)
                 ChangeCipherSpec record ignored (middlebox compat)
                 one coalesced encrypted record (EE|Cert|CV|Finished) -> CONNECTED,
                   application epoch installed, client Finished emitted encrypted
                 server opens & verifies the client Finished
                 application data both directions over the application epoch
   invariant:    tampered ciphertext -> ERR_RECORD, FSM untouched (still WAIT_EE)
   invariant:    valid record, bad Finished -> ERR_PROTOCOL, FSM -> ERROR
   reassembly:   a handshake message fragmented across two records reassembles
```

With the FSM now driven over real encrypted records, the only thing standing
between Aurora and a live `https://` server is trust: parsing the Certificate
chain and verifying CertificateVerify — the X.509 / signature layer (step 12),
which `conn.c` deliberately leaves as a blind transcript for now.

## Step 11b — RFC 8448 trace runner (RFC 8448 §3)

Before touching certificates, the whole protocol engine is frozen against an
authoritative reference: `make tls-trace-test` replays RFC 8448's published
"Simple 1-RTT Handshake" and checks **every derived value byte-for-byte** against
the document. The constants are extracted programmatically from the RFC text, not
transcribed by hand, so the test is a real known-answer baseline.

RFC 8448 negotiates `TLS_AES_128_GCM_SHA256`, while our record layer is
ChaCha20-Poly1305, so the trace's *encrypted records* can't be opened by our AEAD
(that would need AES-GCM, which we don't implement). That is fine: the record
layer is already pinned separately (step 6 + step 11), and what this runner
validates is the **cipher-independent protocol engine** on real RFC bytes — the
same operations the FSM / conn perform internally:

```
RFC 8448 trace:  X25519: client/server public keys + ECDHE shared secret
                 ServerHello parses (cipher 0x1301, key_share) from real bytes
                 Transcript-Hash(ClientHello..ServerHello)
                 Early / Handshake / Master + client&server hs-traffic secrets
                 handshake-epoch write key+iv (server & client) via Expand-Label
                 EncryptedExtensions / Certificate / CertificateVerify framing
                 server Finished verify_data        (== RFC, and our checker accepts it)
                 Transcript-Hash(ClientHello..server Finished)
                 client Finished verify_data        (== RFC)
                 client&server application-traffic secrets + write key+iv
   -> 30 byte-exact checks, TLS TRACE: ALL PASS
```

This is the proof the handshake math is RFC-correct independent of the AEAD and of
certificates: both peers' Finished values and the application secrets reproduce
the RFC to the byte. It freezes a regression baseline so the upcoming PKI layer
can be debugged on its own, never confused with a handshake-engine bug.

## Step 12.1 — ASN.1 DER reader (X.690)

The bottom of the X.509 stack, and the start of a new `x509/` layer (PKI is
neither a pure crypto primitive nor TLS protocol, so it gets its own tree; like
`crypto/` and `tls/` it stays out of the kernel build). `x509/asn1.c` is a
deliberately boring, strict DER reader: a cursor walks a caller-owned buffer one
TLV at a time, with no allocation and no global state.

The one invariant that matters: **the cursor can never read past its buffer.**
`asn1_next` validates before it advances and only commits the cursor on success,
so every downstream parser is automatically bounds-safe. DER (not BER) is
enforced — indefinite length, non-minimal length, an oversized length-of-length,
and the high-tag-number form are all rejected, leaving no encoding ambiguity for
a forged signature to exploit. Helpers: `asn1_expect` (tag-checked read, restores
the cursor on mismatch), `asn1_open` (descend into a constructed element),
`asn1_peek_tag` (for OPTIONAL fields), `asn1_oid_equals`, and `asn1_get_uint`
(minimality-checked, rejects negative / oversized).

`make x509-test` covers every accept/reject path on synthetic TLVs, then walks
the **real RFC 8448 server certificate** — the exact DER our TLS client will have
to parse:

```
ASN.1 basics:    INTEGER / OCTET STRING / long-form length / nested SEQUENCE,
                 peek without consume
ASN.1 rejects:   empty / truncated length / length > buffer / indefinite /
                 non-minimal long form / leading-zero length / high-tag form /
                 oversized length-of-length / negative & non-minimal INTEGER
RFC 8448 cert:   Certificate = SEQUENCE{ tbsCertificate, sigAlg, signatureValue },
                 nothing trails it; descend tbs -> [0] version == 2 (v3),
                 serial == 2, sigAlg OID == sha256WithRSAEncryption,
                 validity = two UTCTime, notBefore == 160730012359Z
```

The RFC 8448 certificate is RSA with `sha256WithRSAEncryption`, which is exactly
why the PKI work goes ASN.1 -> X.509 -> RSA before ECDSA: the same published trace
becomes an end-to-end vector all the way to verifying CertificateVerify. Next
(12.2) is the X.509 parser proper — turning these bytes into a `struct x509_cert`
(subject, issuer, validity, SAN, SubjectPublicKeyInfo, signature) with no trust
decisions yet.

## Step 12.2 — X.509 certificate parser (RFC 5280)

`x509/x509.c` turns a DER certificate into a flat `x509_cert` over the
bounds-checked ASN.1 reader — **no cryptography, no trust decision**. Scope is
kept deliberately tight, exactly the fields a TLS client needs:

- Only the **Common Name** is pulled out of the issuer/subject Distinguished
  Names; the rest of the DN is left alone. CN is diagnostic only — hostname
  matching will use SAN.
- **Validity is normalized to Unix time on the spot** (UTCTime / GeneralizedTime,
  'Z' form), so the later expiry check is just `now >= not_before && now <=
  not_after` — no date strings stored.
- **SubjectAltName dNSName** entries are collected now even though the RFC 8448
  cert has none, because that is what real hostname validation matches against.
- `tbsCertificate`, `SubjectPublicKeyInfo`, the public-key bits and the signature
  are captured as raw slices into the caller's buffer (no copies) — precisely
  what RSA verification (12.3) consumes. The signature is over the raw
  TBSCertificate, so that full element (tag+length+value) is captured verbatim.

The reader's boundedness carries up: every field is read through the cursor, so a
truncated or oversized certificate fails cleanly instead of reading out of bounds.

`make x509-test` checks two certificates — the real reference plus a synthetic one
that exercises the path RFC 8448 cannot:

```
RFC 8448 cert:   version v3, serial 2, issuer/subject CN "rsa", RSA public key,
                 SPKI len 162, TBSCertificate len 281, signature len 128 (RSA-1024),
                 sig OID sha256WithRSAEncryption, validity -> Unix
                 (2016-07-30..2026-07-30), no SAN
synthetic SAN:   subject CN "example.com", issuer CN "Test CA", RSA,
                 san_count == 2 -> "example.com", "www.example.com",
                 validity -> Unix (2024-01-01..2034-01-01)
```

The certificate is now structured data; the last missing piece before trust is
proving the signature over `tbsCertificate`. The RFC 8448 cert is RSA, so 12.3 is
RSA PKCS#1 v1.5 verification — and because the whole chain (ASN.1 -> X.509 -> the
captured `tbs`/`spki_key`/`signature` slices) is already pinned to the published
trace, that step closes a real end-to-end PKI test on RFC bytes.

## Step 12.3 — RSA signature verification (RFC 8017) + the first PKI end-to-end

The crypto/x509 boundary is kept clean: the math lives in `crypto/`, the policy
in `x509/`.

- `crypto/bignum.c` — a fixed-size big integer (32-bit limbs, schoolbook multiply,
  binary long division), the simplest thing that can be correct. No Montgomery, no
  allocation; certificate checks run a handful of times, so clarity beats speed.
  Its KATs (add/sub/mul/cmp/shift/mod/modexp, vs Python) come first and alone, so
  an RSA bug is never a hunt across five places.
- `crypto/rsa.c` — verification only: `rsa_public` (public-exponent modexp) and
  `rsa_pkcs1_v15_verify`. The PKCS#1 v1.5 check is **construct-and-compare** (RFC
  8017 §8.2.2): rebuild the expected `00 01 FF..FF 00 || DigestInfo` and compare,
  instead of parsing the recovered block — no room for a forged DigestInfo or
  short padding (the BERserk class of bugs). RSA knows the envelope, not the hash.
- `x509/verify_cert.c` — the policy seam: hash the TBSCertificate, build the DER
  DigestInfo, **dispatch on the signature-algorithm OID**, and call crypto. RSA +
  SHA-256 is implemented; the dispatcher already has an ECDSA slot that returns
  UNSUPPORTED, so adding ECDSA later needs no restructuring. It proves a signature
  only — no chain, validity-window or hostname decision yet.

`make rsa-test` pins the math; `make x509-test` then closes the first real
**end-to-end PKI test on RFC bytes**. The RFC 8448 certificate is self-signed, so
its own SubjectPublicKey verifies its signature:

```
RFC 8448 cert -> parse -> extract SPKI (modulus, exponent)
              -> SHA-256(TBSCertificate) -> build DigestInfo
              -> RSA public op -> compare EM      => OK
   tamper one TBSCertificate byte                 => BAD_SIGNATURE
   ECDSA signature algorithm OID                  => UNSUPPORTED (dispatch)
```

So ASN.1 ✓, X.509 ✓, RSA ✓ — all on the published reference bytes. What is left is
pure policy, much more tractable than what TLS already required: a trust store
(one root, ISRG Root X1), the validity-window check (now a Unix-time range
compare), and hostname matching against SAN.

## Step 12.4 — trust chain + validity + hostname (RFC 5280 / RFC 6125)

With a signature now provable, this is pure trust *policy* on top of it — no new
crypto. All three live in `x509/verify_cert.c`:

- **Trust chain** — `x509_verify_chain(leaf, roots, root_count)`. v1 is depth 1:
  a root is trusted if its public key validates the leaf's signature, which *is*
  the trust relationship. The array interface is already chain-shaped, so
  intermediate CAs and full DN name-chaining slot in later without an API change.
- **Validity window** — `x509_check_validity(cert, now)` is just
  `not_before <= now <= not_after`, the payoff from normalizing dates to Unix time
  back in 12.2. Distinct NOT_YET / EXPIRED results.
- **Hostname** — `x509_check_hostname(cert, host)` matches against SubjectAltName
  dNSName only (CN ignored, as modern clients require), case-insensitively, with a
  leading `*.` wildcard that matches exactly one left-most label.

`make x509-test` builds a synthetic CA→leaf chain with **real** RSA signatures
(the CA signs the leaf) plus a wildcard SAN, the path RFC 8448 can't exercise:

```
trust:     leaf trusted by its CA root            => OK
           leaf against an unrelated root          => UNTRUSTED
           CA verifies itself (self-signed)        => OK
validity:  now in 2026 / 2023 / 2035  => OK / NOT_YET / EXPIRED
hostname:  example.com, www.example.com (exact, case-insensitive)  => match
           *.test.example vs foo.test.example      => match
           vs a.b.test.example, test.example       => no match (one label only)
           evil.com; CN "rsa" is never used        => no match
```

The PKI engine is now complete for RSA: parse, signature, trust, validity,
hostname. What remains is wiring — `tls_verify_server_certificate(chain, host,
now)` chaining signature→trust→validity→hostname into one call (12.5) — and then
ECDSA P-256 (12.6), the last primitive before a real `https://` fetch (13).

## Step 12.5 — Certificate integration (RFC 8446 §4.4.2)

The point where the handshake stops treating the server's certificate as opaque
transcript bytes and starts deciding whether to trust it. `tls/cert.c` has two
concerns and no cryptography of its own:

- **Message parser** — `tls_parse_certificate` walks the Certificate wire message
  (certificate_request_context + a certificate_list of CertificateEntry) with full
  bounds checks and runs each cert_data through the X.509 parser into a
  `tls_cert_chain`.
- **PKI glue** — `tls_verify_certificate_chain` runs the policy on the end-entity
  certificate: `x509_verify_chain` (trusted by a root) + `x509_check_validity`
  (Unix-time window) + `x509_check_hostname` (SAN), returning one `TLS_CERT_*` code.

This proves the **certificate** (this key belongs to host X, vouched for by a
trusted root). It does *not* prove the peer holds the matching private key — that
is CertificateVerify, the next step.

**FSM integration.** A trust store is now optional on the client
(`tls_client_set_trust`). With one installed, WAIT_CERT parses and validates the
Certificate message, and a failure drives the FSM to ERROR — so a certificate
finally affects TLS state instead of being inert transcript bytes:

```
WAIT_CERT --(PKI ok)--> WAIT_CV
          --(PKI fail)-> ERROR
```

With no trust store the certificate stays transcript-only (engine / replay mode),
which keeps the deterministic loopback and RFC 8448 tests unchanged.

`make tls-test` adds, over the synthetic CA→leaf chain wrapped in a real
Certificate message:

```
parse:  Certificate message -> chain.count 1, leaf CN example.com
glue:   trusted+in-window+host match            => TLS_CERT_OK
        wildcard host foo.test.example          => TLS_CERT_OK
        wrong host / expired / untrusted root    => BAD_HOSTNAME / EXPIRED / UNTRUSTED
        truncated message                        => -1
FSM:    trusted certificate    -> WAIT_CV
        hostname mismatch      -> ERROR
        no trust store         -> accepted (transcript-only)
```

What remains for full server authentication is CertificateVerify — the server's
signature over the transcript with the leaf's private key. In RFC 8448 that is
`rsa_pss_rsae_sha256`, a genuinely new primitive (MGF1 + EMSA-PSS), so it gets its
own step (12.5b: `crypto/mgf1.c` + `crypto/rsa_pss.c` with their own vectors)
before the two halves are joined into one `tls_verify_server_certificate` call.

## Step 12.5b — CertificateVerify (RSA-PSS, RFC 8446 §4.4.3)

The last new cryptography, and the step that turns "this certificate is trusted"
into "the peer actually holds the private key." TLS 1.3 signs CertificateVerify
with `rsa_pss_rsae_sha256`, not PKCS#1 v1.5, so two new primitives land in
`crypto/`, each with its own vectors:

- `crypto/mgf1.c` — MGF1-SHA256 (RFC 8017 §B.2.1), checked against an independent
  Python reference.
- `crypto/rsa_pss.c` — `rsa_pss_sha256_verify`, EMSA-PSS verification (RFC 8017
  §9.1.2) with SHA-256 and salt length == hash length. Verify only, no signing.
  Checked against a real PSS signature produced by an independent toy key.

`tls/cert.c` adds the TLS glue: `tls_verify_certificate_verify` builds the signed
content (`0x20`×64 || `"TLS 1.3, server CertificateVerify"` || `0x00` ||
Transcript-Hash(ClientHello..Certificate)), hashes it, and dispatches on the
SignatureScheme — `0x0804` runs RSA-PSS with the leaf's public key; anything else
is UNSUPPORTED (the ECDSA slot for later). The RSAPublicKey parse is shared with
the PKCS#1 path via `x509_rsa_pubkey`.

The headline check is the **real CertificateVerify from RFC 8448**, verified
byte-for-byte by our from-scratch RSA-PSS + MGF1 (`make tls-trace-test`):

```
Transcript-Hash(ClientHello..Certificate) == RFC value
scheme == rsa_pss_rsae_sha256
CertificateVerify verifies under the leaf key   => TLS_CV_OK
tampered signature / wrong transcript           => TLS_CV_BAD
ECDSA scheme                                     => TLS_CV_UNSUPPORTED
```

Both halves of server authentication are now proven on the published trace: the
certificate (RSA-PKCS#1 over TBSCertificate) and the handshake signature (RSA-PSS
over the transcript). What remains is wiring — joining Certificate +
CertificateVerify at WAIT_CV in the FSM into one `tls_verify_server_certificate`
decision (12.6) — and then a real `https://` fetch (13).

## Step 12.6 — FSM authentication (server authentication as a handshake invariant)

The three proven blocks (certificate chain, CertificateVerify, Finished) existed
side by side; this step makes them a single handshake invariant. With a trust
store installed the FSM now drives:

```
WAIT_CERT --Certificate trusted--> WAIT_CV --CertificateVerify ok--> WAIT_FINISHED
          --reject--> ERROR(CERT)          --reject--> ERROR(AUTH)
```

- **CertificateVerify at WAIT_CV.** The transcript is snapshotted *before* the CV
  message is appended, giving exactly Transcript(ClientHello..Certificate) — the
  boundary RFC 8446 §4.4.3 requires. The leaf public key is captured at WAIT_CERT
  (the parsed slices point into that message, which is gone by WAIT_CV).
- **`peer_authenticated`** flips true only on a successful CertificateVerify — not
  after Certificate, not after Finished. It is the one bit that means "the peer
  proved it holds the leaf private key."
- **Error separation.** `tls_error` distinguishes a rejected certificate
  (`TLS_ERR_CERT`), a failed CertificateVerify (`TLS_ERR_AUTH`) and a framing /
  Finished error (`TLS_ERR_PROTOCOL`), so a future live-HTTPS failure is easy to
  localize.

`make tls-test` runs a full authenticated handshake over the synthetic CA→leaf
chain. Because the library is verify-only, the test plays "server" and signs a
**real** CertificateVerify with the leaf private key (RSA-PSS), exactly as it
already computes the server Finished:

```
Certificate -> WAIT_CV (not yet authenticated)
CertificateVerify (real PSS) -> WAIT_FINISHED, peer_authenticated = 1
Finished -> CONNECTED  (CONNECTED implies authenticated)
tampered CV               -> ERROR(AUTH), peer_authenticated = 0
CV over the wrong transcript (CH..SH) -> ERROR(AUTH)   [pins the snapshot boundary]
bad hostname              -> ERROR(CERT) before any CV
```

CONNECTED is now a cryptographically meaningful state: the certificate is trusted,
the hostname matched, the validity window held, the server proved key ownership,
and the Finished verified. The TLS 1.3 client is logically complete for RSA — what
remains is integration with the real internet (step 13: TLS over sockets, a first
HTTPS GET), then intermediate-CA chains and ECDSA.

## Step 13.0 (logging) — handshake tracing

Before any live socket, the handshake gained tracing — because the first real
failures otherwise read as a bare "CONNECT FAILED" with no clue where. `tls/trace.c`
defines **semantic events** (not strings); the FSM and the record layer emit
milestones and failures through a per-connection sink (no globals, no printf in
the freestanding code). A host test installs a sink that records the sequence;
AuroraOS will install one that prints `[TLS] <event>` to the serial log.

```
[TLS] ClientHello sent
[TLS] ServerHello received        [TLS] Handshake keys installed
[TLS] EncryptedExtensions received
[TLS] Certificate received        [TLS] Certificate chain OK
[TLS] CertificateVerify OK        [TLS] Peer authenticated
[TLS] Finished OK                 [TLS] Application keys installed
[TLS] CONNECTED
```

Failures are equally explicit and carry the locus: `Certificate validation FAILED`,
`CertificateVerify FAILED`, `Unsupported SignatureScheme` (with the scheme), or
`Record decrypt FAILED`. `make tls-test` drives a full authenticated handshake with
a recording sink and asserts the exact milestone sequence, and that a tampered
CertificateVerify ends the trace at the AUTH failure.

This is the first piece of step 13: the diagnostics are in place, so when the FSM
is bound to a real TCP socket the trace will pinpoint whichever integration issue
surfaces first (fragmented records, a longer chain, an ECDSA leaf, ...).

## Step 13.0a — network audit + TLS record reader

Going live splits into a written audit and the one genuinely new layer.

**Audit** (`docs/NET_SEMANTICS.md`): the socket layer pinned in writing before any
integration — recv is a blocking byte stream with no partial-read guarantee and an
ambiguous `0` (peer close *or* 10 s idle), send is stop-and-wait, ownership is
copy-in/copy-out, the RX path is pumped only inside a socket syscall, and — the
headline defect — the 8 KiB per-connection receive buffer never compacts, so a
connection can take at most ~8 KiB total and silently drops-yet-ACKs the rest.
That buffer must be fixed before a real handshake (13.0b.0).

**Record reader** (`tls/record_reader.c`): the bottom seam, turning the TCP byte
stream into complete TLS records. Source-agnostic by construction — feed it bytes
from anywhere, pull records out — so the same code serves host tests, recorded
traces, a socket, and a fuzzer. A returned record points into the reader's buffer
and is valid until the next feed; drain with `next()` until it returns 0, then
feed more. `make tls-test` covers the seven framing cases that bite real streams:

```
1 header + body delivered one byte at a time -> one record
2 whole header, then body byte-by-byte
3 two coalesced records in one chunk -> two records
4 a split inside the SECOND record's header
5 zero-length body (a valid 5-byte record)
6 length limit: 2^14+256 accepted, one over -> error
7 truncated stream: need-more + bytes pending (EOF here = truncated, not a record)
```

With framing proven deterministically, 13.0b binds it to a real socket: fix the
rx buffer, then drive a handshake to CONNECTED against a local RSA `s_server`.

## Step 13.0b.0 — TCP receive ring (the transport fix under TLS)

The audit's headline defect, fixed before any live handshake. The old
per-connection buffer used a write cursor (`rx_len`) that reads never rewound, so
a connection could absorb at most one bufferful **over its entire lifetime** and,
once full, advanced `rcv_nxt` over bytes it had dropped — silently ACKing data it
never stored. That is a transport reliability defect, not a TLS issue, so it was
fixed at the transport layer and proven independently of TLS and of QEMU.

Split into two commits so a post-integration regression localises instantly:

- **13.0b.0a — `net/rxring.c`**: a fixed 16 KiB byte ring (`push`/`pop`/`used`/
  `free`). A pure data structure — no TCP, sequence, or window knowledge; the
  accept/drop *policy* stays in the caller. Freestanding (explicit byte copies,
  no `memcpy`) so one source compiles into both the kernel and the host test.
  `make rxring-test` proves FIFO order, partial-pop continuation, refusal to
  overflow, wrap-around ordering, the exact full/empty boundaries, and — the
  point — ~640 KiB flowing through the 16 KiB ring over 10 000 push/pop cycles.
- **13.0b.0b — `net/tcp.c` migration**: `tcp_recv` pops from the ring (freeing
  space) and sends a window update when it reopens a window it had advertised as
  0; `tcp_input` accepts a segment **all-or-nothing** and never advances
  `rcv_nxt` over bytes it didn't store (a non-fitting segment is dropped so the
  peer retransmits once space frees); `rcv_wnd` carries the real free window on
  every segment. 16 KiB sits comfortably above one max wire record (2^14+256)
  and a multi-KiB certificate chain.

Conservative choice: all-or-nothing per segment rather than partial acceptance,
which would need careful `rcv_nxt`/ACK/window recomputation the simple stack
isn't built for yet. QEMU acceptance (run on the Aurora side): a >8 KiB response
keeps arriving past the first 8 KiB, and a slow 32-byte-at-a-time reader against
a flooding sender keeps progressing (window release + buffer reuse).

## Step 13.0b.1 — the handshake driver (off the wire, deterministically)

The top seam that finally connects the byte transport to the engine:

```
transport (socket)  ->  tls_record_reader  ->  tls_conn  ->  CONNECTED
```

`tls/driver.c` is deliberately thin — all the protocol logic already exists below
it (`tls_conn` does record binding / epoch switching / message reassembly;
`tls_record_reader` does framing). The driver only owns the control loop: send the
ClientHello, pull complete records out of the reader, feed each to `tls_conn`, send
back anything it emits (the client Finished), and stop the instant the FSM reaches
CONNECTED. It is **transport-agnostic** — it touches the network only through a
`tls_transport` of `read`/`write` callbacks — so the identical driver runs over a
kernel socket fd and over a host-test mock. Outbound flights go through `send_all`,
which loops over `write` and never assumes a full write (Aurora's `tsk_write` can
report a short count).

Because the transport is a callback, the record-stream handling — the part most
likely to bite on a real server — is proven **deterministically, off the wire**.
`make tls-test` builds one authenticated server flight (real synthetic chain + a
real RSA-PSS CertificateVerify), seals it into wire records the way `s_server`
does (SH plaintext, then EE | Certificate | CertificateVerify | Finished each as
its own encrypted record), and runs the driver to CONNECTED under adversarial
read/write chunkings:

```
all-at-once   five records in a single read            -> CONNECTED + full trace
byte-by-byte  read 1 / write 1                          -> CONNECTED + full trace
split mid-Certificate  a read boundary inside the cert  -> CONNECTED + full trace
partial writes  write() accepts 1 byte at a time        -> output byte-identical
truncated flight (no Finished)                           -> EOF, never "connected"
```

The clean run is checked end to end both ways: the full client milestone trace
(ClientHello sent → … → CONNECTED) fires, and the captured client output is a
valid ClientHello followed by an encrypted Finished that **verifies server-side**
with the client handshake-traffic key. With this, the TLS engine is no longer a
lab test — it drives a real handshake to CONNECTED from nothing but a byte stream.
What remains for 13.0b.2 is purely the socket adapter (fd → `tls_transport`) and a
QEMU run against a local `openssl s_server -tls1_3`.

## Step 13.0b.2 — TLS over a real socket (`tlsconnect`)

The driver finally meets the network. First a written audit of the userspace seam
(`docs/NET_SEMANTICS.md` §8): the program reaches TCP only through `inet_socket` /
`inet_connect` / `read` / `write` / `close`, and every contract subtlety the driver
must honour — `0` = EOF is fatal before CONNECTED, `<0` = error, a short `write`
keeps going — is already handled. The transport adapter is the expected four-liner
(`read`/`write` over the fd).

Two small commits make it runnable:

- **13.0b.2a — IP-literal connect** (`net/tcpsock.c`): `inet_connect` only did DNS,
  so the guest could not address the QEMU host (`10.0.2.2`) where the test server
  runs and which no resolver knows. A dotted-quad host is now used directly; real
  names still fall through to DNS. This splits "where to connect" (an IP) from "who
  to trust" (the certificate name), which is exactly what a local self-signed test
  needs.
- **13.0b.2b — `user/tlsconnect.c`**: `inet_connect` → `tls_driver_handshake` →
  print the milestone trace → exit. Deliberately narrow — no HTTP, no application
  data (that is 13.0b.3). The trust root is **embedded** (`user/tls_test_root.h`,
  generated by `tools/der2c.py` from `test/tls/cert.pem`), so no filesystem is
  involved; the certificate is checked against its SubjectAltName `aurora-test`
  while the TCP connection goes to the given IP. The ~79 KiB of TLS state lives in
  BSS, never on the 16 KiB user stack; RSA/bignum verification peaks well inside it.

The embedded root is verified on the build host through Aurora's *own* X.509 code
before it is ever trusted in QEMU: it parses, validates at the pinned `now`, matches
`aurora-test` (and rejects a wrong name), and its self-signed chain verifies. What I
cannot do here is run QEMU; the live pass belongs to the Aurora side:

```
# host: a throwaway RSA test server matching the embedded root
openssl s_server -accept 4433 -cert test/tls/cert.pem -key test/tls/key.pem -tls1_3
# guest (Aurora shell): connect to the QEMU host
tlsconnect 10.0.2.2 4433
```

Success is not just "CONNECTED" but the whole chain appearing over real TCP —
`ClientHello sent → ServerHello received → Handshake keys installed → Certificate
chain OK → CertificateVerify OK → Finished OK → Application keys installed →
CONNECTED` — with no change to the crypto or the FSM. That is the strongest
integration result in the TLS branch: TCP → TLS 1.3 → X.509 → RSA-PSS, live.

(`test/tls/key.pem` is a throwaway self-signed test key and is intentionally **not**
committed; only the public `cert.pem` and the embedded DER are in the tree.)

## Step 13.0b.3 — application data over the live epoch

CONNECTED only proves the handshake. The harder thing to get right is the *first
protected application record*: it rides a **new encryption epoch** (the application
traffic keys), with its own sequence number restarted at 0 and its own nonce
derivation, and it must interoperate with OpenSSL on app data, not just handshake
messages. So `tlsconnect` continues past CONNECTED: it seals one record
(`tls_conn_send_app`, default `"PING\n"`), then drains replies
(`tls_conn_recv_app`), printing each, until the peer closes or the idle window
elapses. NewSessionTickets — handshake messages OpenSSL sends *inside* app-data
records right after the handshake — are accepted and ignored, so they do not
derail the exchange.

The deterministic proof is in `make tls-test`: after driving to CONNECTED through
the mock transport, the test exchanges application data with the server mirror's
application keys and checks, byte-for-byte:

```
client -> server  record #0 ("PING")   server decrypts
client -> server  record #1             decrypts -> client app tx seq advanced
server -> client  record #0 ("PONG")    client decrypts
server -> client  record #1             decrypts -> client app rx seq advanced
server -> client  NewSessionTicket      accepted, yields no app data
server -> client  tampered record       AEAD rejects -> ERR_RECORD
```

That pins the four things app data can break on independently of the handshake:
the application secrets match end to end, the per-epoch sequence numbers advance in
both directions, the nonce derivation holds, and seal/open round-trip with a real
peer. QEMU acceptance (Aurora side): run the same `s_server`, then `tlsconnect
10.0.2.2 4433` — `PING` appears on the server console, and whatever you type back
there is printed by `tlsconnect` as a decrypted reply. A round-trip means the TLS
channel — not just the handshake — lives over real TCP.

With that, the highest remaining risk for the real web is no longer the handshake
or app data but the **signature scheme**: most sites authenticate with ECDSA
P-256 (`ecdsa_secp256r1_sha256`), which the dispatcher currently answers
UNSUPPORTED. That, not an HTTPS client, is the next major block (13.x).

## Step 13.0b.4 — oversized certificate chain (the next buffer risk)

A local self-signed cert barely exercises reassembly; a real server sends a
multi-cert chain (leaf + intermediate + extensions) of several KB. The previous
buffer defect (`rx_buf`) was found by reasoning about lifetime; this one is found
the same way, before the wire. `make tls-test` now drives a **two-cert** chain
(leaf + CA) sealed into ~20 tiny records, with the transport reads deliberately
misaligned to record boundaries — the worst case for the reader's framing and the
conn's message reassembly at once. It reaches CONNECTED with both certificates
parsed. The companion check is the safety guard: a Certificate message whose
declared length exceeds the reassembly buffer (`TLS_CONN_HS_BUF`) is rejected with
`ERR_CAPACITY` the moment its header is seen — never buffered, never overflowed,
never a silent CONNECTED. So a genuinely large or hostile chain fails closed
rather than corrupting memory.

## Step 13.x.1–13.x.3 — ECDSA P-256 verify (the real-web signature scheme)

RSA got Aurora to CONNECTED, but most of the live web authenticates with ECDSA
P-256 (`ecdsa_secp256r1_sha256`). Built bottom-up as separate, independently
KAT'd pieces so a failure localizes to one layer:

- **13.x.1a/1b — field (mod p) and scalar (mod n) as separate rings**
  (`crypto/p256_field.c`, `crypto/p256_scalar.c`): different moduli, different
  files, each checked against Python vectors over edge values (0/1/p−1/n−1,
  near-2^256), including `a·a⁻¹ ≡ 1` and the range checks verification needs.
- **13.x.2 — points in Jacobian coordinates** (`crypto/p256_point.c`): the
  identity is an explicit infinity flag, not magic coordinates; add/double need no
  inversion (one inversion per scalar-mul, at the end). Tested geometry-first
  (double/add on known points, then group invariants G+O / G+(−G)=O / 2G=G+G /
  3G=2G+G), then 9 independent `k·G` vectors, then **n·G = O** — the order check
  that, alongside the `k·G` vectors, makes a hidden formula bug very unlikely.
- **13.x.2b — public-key validation** (`p256_pubkey_decode`): rejects wrong
  length/prefix, X or Y ≥ p, off-curve points, and (defense in depth) any point
  with n·Q ≠ O. Tested with valid keys and a battery of invalid ones.
- **13.x.3 — ECDSA verify** (`crypto/ecdsa.c`): a strict X9.62 DER parser
  (rejects non-minimal/indefinite lengths, trailing bytes, negative/zero-padded
  integers, over-long magnitudes) feeding the `s⁻¹` / `u1·G + u2·Q` /
  `x_R ≟ r mod n` equation. Validated against the **official Google Wycheproof
  set — all 484 vectors pass** (174 valid accepted, 310 invalid rejected),
  covering exactly the edges that break ECDSA implementations: r/s = 0 or ≥ n,
  modified hash/signature, malformed DER, leading zeros, edge values near n.

This is the ECDSA analogue of RFC 8448 for the handshake: the negative Wycheproof
cases are the real test. The work is verify-only and uses public data, so nothing
is constant-time.

**Performance note (optimization pulled forward).** The field was first written
on the verified `bignum` (correct but slow): one verify measured ~675 ms, so the
484-vector Wycheproof run took ~5.5 min — too slow to be a routine test, and
borderline for a live handshake. So the fast field reduction the roadmap deferred
was brought forward: P-256's prime lets `value = low + high·2^256` reduce as
`low + high·R0` with R0 = 2^224−2^192−2^96+1, and since 224/192/96 are whole
32-bit words the folds are word-aligned shifts with no bit-twiddling, staying
non-negative so the loop converges to one final subtract. Same `fe` API, so the
13.x.1a KATs and all 484 Wycheproof vectors re-validate it unchanged: verify
dropped to ~17 ms and the full suite to ~8 s. The scalar ring stays on `bignum`
(a handful of ops per verify); a fast mod-n is a later, optional step.

## Step 13.x.4 — ECDSA in the X.509 seam

With the curve math proven, the remaining risk moved out of cryptography and into
the ASN.1/X.509 join: `SPKI → 04‖X‖Y → validate → ecdsa_verify`. Two small wires:

- **Parse-time named-curve check** (`x509/x509.c`): an EC `SubjectPublicKeyInfo`
  is only classified `X509_PK_EC` when the AlgorithmIdentifier carries
  `id-ecPublicKey` **and** the `prime256v1` (P-256) parameters OID. A key on any
  other curve is left `UNKNOWN` rather than letting a non-P-256 point reach the
  P-256 verifier. For an EC key the BIT STRING contents are already the
  uncompressed point `0x04‖X‖Y`, i.e. exactly `ecdsa_p256_verify`'s `pub`.
- **Dispatcher branch** (`x509/verify_cert.c`): the `ecdsa-with-SHA256` OID, which
  previously returned `UNSUPPORTED`, now hashes the TBSCertificate and calls
  `ecdsa_p256_verify(issuer_key, SHA-256(tbs), signature)`. The verifier fully
  re-validates the key (length/prefix, coords < p, on-curve, subgroup) and parses
  the signature strictly, so a spoofed `sig_oid` pointing an ECDSA algorithm at a
  non-EC key fails the key decode instead of being trusted.

Validated with a real `openssl`-generated ECDSA P-256 cert
(`test/tls/ec_cert.pem`, embedded in the host test) against the three KATs the
plan called for:

| KAT | input | result |
|-----|-------|--------|
| #1 | unmodified self-signed cert | **PASS** (and trusts itself via `x509_verify_chain`) |
| #2 | one byte flipped in TBSCertificate | **FAIL** (`BAD_SIGNATURE`) — proves the body is actually hashed, not just parsed |
| #3 | one byte flipped in the signature | **FAIL** (`BAD_SIGNATURE`) — exercises the dispatcher + DER signature path |

After this, `RSA certificates PASS` and `ECDSA certificates PASS`. The kernel
image is untouched (x509/ is outside its source set); the userspace HTTPS client
(`tlsconnect.elf`) now links the ECDSA/P-256 objects via `verify_cert.c`. ECDSA is
**not yet** wired into the TLS CertificateVerify handler or advertised in the
ClientHello `signature_algorithms` — that is 13.x.5, and until then a server will
still pick RSA or abort. The throwaway EC private key (`test/tls/ec_key.pem`) is
gitignored, like the RSA test key.

## Step 13.x.5 — ECDSA in the TLS CertificateVerify seam

The certificate chain proves *whose* key it is; CertificateVerify proves the peer
*holds* that key, by signing the handshake transcript. Two wires, governed by two
invariants:

- **Dispatch on the SignatureScheme, not the certificate key type**
  (`tls/cert.c`). The signed content (`0x20`×64 ‖ context ‖ `0x00` ‖
  transcript-hash) is built once, then a `switch (sig_scheme)` routes to
  `rsa_pss_rsae_sha256` or `ecdsa_secp256r1_sha256`. TLS authenticates the
  *signature*, whose algorithm is named in the message — so the message is the
  source of truth, and a scheme/key mismatch fails inside the per-scheme verifier
  rather than being silently accepted.
- **One extensible advertised list** (`tls/handshake.c`). The ClientHello
  `signature_algorithms` extension is emitted from a single
  `static const uint16_t tls_sigalgs[]` (ECDSA-P256, RSA-PSS, RSA-PKCS1), so
  adding a scheme later is one line, not edits scattered across the writer. The
  SignatureScheme code points live in one header (`tls/cert.h`).

The 2×2 dispatch matrix is the test that matters — crossed scheme/key is exactly
where a dispatcher keyed on the wrong thing breaks:

| signature | scheme announced | result |
|-----------|------------------|--------|
| RSA-PSS, RSA key | `rsa_pss_rsae_sha256` | **OK** |
| ECDSA, EC key | `ecdsa_secp256r1_sha256` | **OK** |
| RSA-PSS, RSA key | `ecdsa_secp256r1_sha256` | **BAD** — RSA key isn't a P-256 point |
| ECDSA, EC key | `rsa_pss_rsae_sha256` | **MALFORMED** — EC point isn't an RSAPublicKey |

Both PASS cases use real signatures over a fixed transcript hash (RSA-PSS signed
in-test, ECDSA signed by `openssl dgst -sha256 -sign` with `ec_key.pem`); tamper
and wrong-transcript variants reject, and an unimplemented scheme (ed25519) still
returns `UNSUPPORTED`. The RFC 8448 trace test's old "ECDSA → UNSUPPORTED" check
now correctly reads "RSA key under ECDSA scheme → BAD".

After this the client can verify **both** an RSA and an ECDSA CertificateVerify
and advertises both, so cryptographically it understands most modern servers.
What remains before a real site is 13.x.6: prove a full ECDSA server flight
(Certificate + CertificateVerify + Finished) drives the existing FSM/driver to
CONNECTED with no special-case branch.

## Step 13.x.6 — full ECDSA flight reaches CONNECTED

The proof that the two new seams (X.509 ECDSA, ECDSA CertificateVerify) actually
compose: a complete server flight — EncryptedExtensions, an EC Certificate, an
ECDSA CertificateVerify, and Finished — is fed through the **same** `tls_client`
FSM that handles RSA, and it reaches CONNECTED. The FSM has no `if (ecdsa)`
branch; it dispatches on the certificate's algorithm and the CertificateVerify's
SignatureScheme, so the ECDSA path is just data flowing through the RSA machinery.
One flight exercises both 13.x.4 (the self-signed EC cert verifies as its own
trust root) and 13.x.5 (the ECDSA CertificateVerify over the live transcript).

Scope is deliberately narrow — no HTTP, no GET, no application data, no external
network, no OpenSSL. Just: does the handshake authenticate and connect?

- **PASS:** Certificate → WAIT_CV → CertificateVerify → WAIT_FINISHED
  (`peer_authenticated` set) → Finished → CONNECTED.
- **Test A (forged CertificateVerify):** flip a signature byte → `FAIL_AUTH`,
  never CONNECTED, `peer_authenticated` stays 0.
- **Test B (forged Finished):** valid CV, then flip a Finished byte → rejected,
  never CONNECTED. A bad Finished is an integrity failure (`TLS_ERR_PROTOCOL`),
  classified separately from CertificateVerify's peer-auth failure
  (`TLS_ERR_AUTH`); `peer_authenticated` was already set by the valid CV, which is
  correct — the peer *did* prove key possession; the transcript MAC is what broke.

**Test-only ECDSA signer.** Producing a CertificateVerify over the *live*
transcript (rather than fragile pre-recorded bytes) needs a signer; the library
is verify-only by design, so this lives in the test harness as `ecdsa_sign_for_test`
— the exact analogue of the existing RSA `pss_sign_cv`. It is a testing tool, not
a new TLS-client capability: nothing is added to `crypto/`. It signs with a
SEPARATE throwaway EC key (`test/ec_test_key.pem`, gitignored; the cert DER and
private scalar are embedded as constants in the test, like the RSA `T_LEAF_*`
pair). That key is never used in QEMU, `openssl s_server`, the trust store, or any
live certificate — production secrets ≠ test secrets.

With this, FSM authentication is proven on both paths (RSA and ECDSA) with no
special-casing. The remaining risk is no longer in the cryptography but in real
certificate chains, intermediate CAs, chain sizes, HTTP/1.1, and live-server
behavior — a different class of problem, which is **Phase 14.0 (Real Internet
HTTPS)**.

# Phase 14.0 — Real Internet HTTPS

The cryptography and authentication are done; this phase is about *realism*. Its
character is different from everything before it: earlier steps proved new math,
this one proves the **absence of missing policy**. A bug like "CA:FALSE accepted
as a CA" or "leaf used as an intermediate" is far likelier now than a flaw in
SHA-256 or ECDSA, because the crypto has been validated many times over. So the
tests here lead with the *negative* cases.

## Step 14.0.1 — intermediate CA support (depth-N path building)

Real servers send `leaf → intermediate → root`, not a leaf signed straight by a
root. `x509_verify_chain` is now a depth-N builder (`chain[0]` = leaf,
`chain[1..]` = intermediates in any order; the trust store holds the roots):

- **Path building** — from the leaf up, each link finds its issuer by matching the
  child's raw issuer DN to a candidate's raw subject DN **and** verifying the
  child's signature with that candidate's key. It stops when a trusted root signs
  the current cert. DN comparison is byte-for-byte on the captured Name DER (RFC
  5280 permits this when encodings match, as they do for CA-issued certs; it can
  only fail closed). A depth bound also stops issuer cycles.
- **basicConstraints** — any cert used as an *issuer* (an intermediate) must have
  `cA = TRUE`; otherwise any leaf could be reused to sign others. Trust anchors in
  the store are not themselves re-checked (they are anchors by definition).
- **keyUsage** — if present, an issuer must assert `keyCertSign`. (An absent
  KeyUsage does not restrict usage, per RFC 5280.)

Deliberately deferred (not needed for a first real connection): pathLenConstraint,
NameConstraints, PolicyConstraints, CRL, OCSP, AIA fetching.

Tested against a real openssl ECDSA P-256 PKI, leading with the rejections:

| chain | result |
|-------|--------|
| leaf → intermediate(CA,keyCertSign) → root | **OK** |
| leaf alone, no intermediate to reach the root | **UNTRUSTED** (broken chain) |
| leaf → issuer with **basicConstraints CA:FALSE** → root | **BAD_CA** |
| leaf → issuer **CA:TRUE but no keyCertSign** → root | **BAD_CA** |
| valid 2-cert chain, but the anchor is an unrelated root | **UNTRUSTED** |

The two `BAD_CA` rows are the ones that matter — they are exactly the
"non-CA used as a CA" mistake. With them green, Aurora's PKI stops being a
lab toy (depth-1, signature-only) and starts to resemble a real browser path
validator. The userspace HTTPS client picks this up for free (`verify_cert.c` is
shared). Next, 14.0.2: embed a real root (ISRG Root X1) and validate a captured
live chain offline.

## Step 14.0.2 — validating a real Let's Encrypt chain, offline

The first contact with genuine internet PKI, before any live socket. A real
chain was captured from `www.eff.org` and is embedded in the test:

```
*.eff.org (RSA-2048) → LE "YR1" (RSA-2048) → ISRG "Root YR" (RSA-4096) → ISRG Root X1 (RSA-4096)
```

The server sends the leaf + two intermediates; **ISRG Root X1** is the trust
anchor. It really chains to the published ISRG Root X1 (cross-checked with
`openssl verify`), so this exercises the depth-N builder, byte-exact DN chaining,
the CA checks, and RSA-PKCS1-SHA256 verification (incl. RSA-4096) on bytes nobody
crafted for us. Four cases, leading with the rejections so a pass can't be a false
positive:

| case | result |
|------|--------|
| real chain + ISRG Root X1 (+ validity + `www.eff.org` vs `*.eff.org`) | **OK** |
| drop the YR1 intermediate (broken path) | **UNTRUSTED** |
| flip one byte of YR1's signature | **BAD_SIGNATURE** |
| same chain under an unrelated trust anchor | **UNTRUSTED** |

Case 3 motivated a builder refinement: a link whose issuer is found *by name* but
whose signature fails now yields `BAD_SIGNATURE`, distinct from `UNTRUSTED` (no
issuer found at all) — so "tampered" and "incomplete" are told apart.

**Finding — an algorithm-coverage gap, not a plumbing gap.** The first chain tried
was `letsencrypt.org` itself, which today serves an **ECDSA** chain: the leaf is
signed by intermediate **E7**, and E7 is **ECDSA P-384 / SHA-384**. Aurora
implements ECDSA **P-256 / SHA-256** only — no P-384, no SHA-384 — so it cannot
verify that leaf's signature. This is the real shape of the remaining work: the
TLS/PKI machinery is correct, but a slice of the live web uses curves/hashes
Aurora hasn't implemented. RSA chains (and ECDSA-P256 chains) work today; P-384/
SHA-384 is filed as **14.x** for when ECDSA LE sites are needed. The RSA chain
above is fully representative for a first real connection.

## Memory footprint (measured before going live)

Exact i686 sizes (compiled `--target=i686-elf -m32`, read from symbol sizes), so
the resource budget is known before a real server sends a chain heavier than the
synthetic tests:

| item | size | notes |
|------|------|-------|
| `sizeof(tls_conn)` | 43,916 B (42.9 KiB) | incl. 32 KiB handshake reassembly + the FSM |
| `sizeof(tls_record_reader)` | 33,044 B (32.3 KiB) | byte-stream → record buffer (one 16 KiB record + slack) |
| `sizeof(tls_client)` (the FSM) | 11,032 B | incl. `tls_cert_chain` 9,636 B |
| `sizeof(x509_cert)` | 2,408 B | dominated by `san_dns[8][256]` = 2 KiB |
| `tlsconnect.elf` **BSS** | 83,480 B (81.5 KiB) | g_conn + g_reader + g_root + two 2 KiB scratch buffers |
| `tlsconnect.elf` text | 64,410 B (62.9 KiB) | code |

- **Peak stack ≈ 9.5 KiB** against a **16 KiB** user stack (USTACK_PAGES=4): the
  RSA verify path dominates (`bignum_modexp` 4,144 B + `bignum_modmul` 2,092 B +
  `bignum_mul` 1,068 B + `rsa_pss` 1,168 B + callers). Crucially, **path building
  is a loop**, so peak stack is independent of chain depth, and certs are parsed
  in place — a heavier chain grows *buffer* use, not stack. The ECDSA-P256 path is
  far lighter (~3 KiB). bignum frames are already sized for the 8192-bit worst case.
- **Peak heap = 0.** The crypto/TLS/x509 path uses no dynamic allocation
  (freestanding); everything is static or stack.
- **Chain limits:** `TLS_MAX_CHAIN = 4` certs (extras in a Certificate message are
  skipped); a Certificate message larger than `TLS_CONN_HS_BUF = 32 KiB` is
  rejected with `ERR_CAPACITY`. Real chains are 3–8 KiB / 2–3 certs, comfortably
  inside both. The one value to watch is `TLS_MAX_CHAIN`: a server sending
  leaf + 2 intermediates + root (4) is at the limit; cheap to raise to 6 (+4.8 KiB)
  if a real site needs it.

## Step 14.0.3a — live Internet TLS, on the host, through Aurora's real engine

Aurora's `crypto/`+`tls/`+`x509/` is portable freestanding C — the very objects
that link into the QEMU userspace client. `tools/tls_live_test.c` runs that engine
against a **real external TLS 1.3 server**, using host sockets only as the byte
transport (through the environment's egress proxy via an HTTP `CONNECT` tunnel).
This catches the real-world behaviours that a synthetic test never will —
record coalescing, fragmentation, post-handshake messages, real timing/EOF — on
genuine bytes, *before* the QEMU bring-up. Narrow criterion (no HTTP parsing):

```
TCP → proxy CONNECT → Aurora tls_driver → CONNECTED → decrypt ≥1 real application_data record
```

**Result — PASS.** Against a live TLS 1.3 server reached through the sandbox's
TLS-inspecting egress proxy, Aurora ran the whole flight with no special-casing:
ClientHello → ServerHello → handshake keys → EncryptedExtensions → Certificate →
**chain verified** (depth-2, RSA, against the proxy's CA, pre-trusted out of band
from `/root/.ccr/agent-proxy-ca.crt`) → **CertificateVerify OK** (rsa_pss_rsae_
sha256) → Finished → application keys → **CONNECTED**. It then sealed a client
application record and **decrypted the server's application_data response** — the
full app epoch (traffic keys, per-epoch sequence, nonce derivation) on real bytes.
The diagnostic trace the step added (`Certificate depth=2`, `Leaf key=RSA`,
`CV scheme=rsa_pss_rsae_sha256`, handshake byte count, per-record sizes) made the
single round trip legible.

Because this sandbox's proxy terminates and re-issues TLS (its CA is in the
environment trust store), the peer here is the *proxy's* TLS 1.3 stack — a real,
independent, standards-compliant implementation, not Aurora's loopback and not a
crafted server. Verification is real (a pre-trusted anchor, not trust-on-first-
use).

**Genuine public servers — the engine works, blocked only by the algorithm gap.**
Pointed at the genuine public `letsencrypt.org` (TLS 1.3, ChaCha20-Poly1305,
X25519, real ISRG Root X1 embedded), Aurora negotiates and runs all the way
through ServerHello → keys → EncryptedExtensions → Certificate, then stops at
chain validation — because that chain's leaf is signed by the **E7** intermediate,
which is **ECDSA P-384 / SHA-384** (see 14.0.2). So the TLS 1.3 machinery
interoperates with genuine public servers; the only thing standing between Aurora
and a fully-verified public connection is P-384/SHA-384 support (filed as 14.x).
RSA and ECDSA-P256 chains verify today.

`make tls-live-test` runs it (needs outbound network); host/port and the trust
anchor (`AURORA_TRUST_PEM`) are overridable for other environments. Default falls
back to the embedded ISRG Root X1.

## Step 14.0.4 — HTTP/1.1 GET over the live TLS channel

With live TLS proven, the last layer of the browser network stack: a real
HTTP/1.1 request/response over the established connection. The harness (same
`tools/tls_live_test.c`) now, after CONNECTED, seals a
`GET / HTTP/1.1` (with `Host` and `Connection: close`) over the application
epoch, reads every `application_data` record until the server closes, reassembles
the response, parses the status line, and decodes the body — **chunked**
(Transfer-Encoding) or **Content-Length**, falling back to read-until-close.

**Result — PASS.** Against a real server, Aurora returned
`HTTP/1.1 200`, ~5 KB of headers, and a **240 KB de-chunked body** — the actual
homepage HTML — reassembled across many `application_data` records. That single
fetch stresses exactly the things a synthetic test can't: a multi-record body,
chunked transfer-encoding, app-epoch sequence numbers advancing over a long
stream, and a clean `Connection: close`.

```
TCP → TLS 1.3 → HTTP/1.1 → 200 OK + body     (all Aurora's own code)
```

This is the milestone where Aurora **fetched a web page from the internet over
its own TCP, TLS 1.3, and HTTP stack** — a far more meaningful boundary than one
more curve. (HTTP parsing here is intentionally minimal: status + body framing,
no redirects/keep-alive/caching; that is application-level polish, not stack
correctness.)

## Step 14.0.3b — `user/httpsget.c`, the userspace HTTPS client

The same proof, but as a real Aurora program over Aurora's *own* network stack
(not host sockets): the acceptance test for the whole user-facing chain.
`user/httpsget.c` links the identical freestanding TLS/x509/crypto objects as the
host harness and does `DNS → TCP → TLS 1.3 → HTTP/1.1 GET → status + body`,
deliberately dumb (no keep-alive, redirects, cookies, compression, HTTP/2).

```
httpsget github.com /
  [TLS] ... CONNECTED
  HTTP/1.1 200 OK
  [body ...]
```

Trust store (as of 14.x.7): a curated set of public **RSA** roots (`user/ca_roots.h`:
ISRG Root X1, DigiCert Global Root CA/G2, USERTrust RSA, GTS Root R1), so a site
whose whole chain is RSA-PKCS1-SHA256 or ECDSA-P256-SHA256 verifies. (RSA roots
specifically, because the anchor's key verifies the intermediate's signature — an
ECDSA-P384 root would re-introduce the 14.x gap one level up.) Expanding this set
is 15.1, once P-384 closes that gap.

Built and host-verified: it compiles and links into `httpsget.elf` (BSS ≈ 147 KiB
— the conn + reader + 5-root store + a 32 KiB response buffer), the kernel image
is unchanged (additive invariant holds), and the 5-root store parses and verifies
the real Let's Encrypt chain from 14.0.2 (ISRG Root X1 matches).

## Step 15.1 — trust store expansion: ECDSA P-384 roots

With ECDSA P-384 closing the "anchor can't verify an EC intermediate" gap (14.x),
the trust store gains three production ECDSA roots, fetched directly from their
issuers (not the host's local CA bundle): **ISRG Root X2** (Let's Encrypt) and
**GTS Root R3** / **GTS Root R4** (Google Trust Services) — all secp384r1.
`user/ca_roots.h` now carries 8 roots (5 RSA + 3 ECDSA P-384); `CA_ROOTS_N` and
every consumer (`g_roots[]`, `tls_client_set_trust`) are sized off that constant,
so the change is purely additive data, no logic touched.

Verified two ways:
- **Host, against Aurora's own parser/verifier** (not openssl): all 8 roots parse
  (the 3 new ones report `pubkey_algo == X509_PK_EC384`), and each new root's
  self-signature verifies under `x509_verify_signature` using Aurora's
  `ecdsa_p384_verify` on the real production DER — not a synthetic test vector.
  (The three pre-existing RSA roots whose self-signature uses SHA-1 or an
  unimplemented `sha384WithRSAEncryption` correctly report `UNSUPPORTED`; this is
  pre-existing and irrelevant to trust — `x509_verify_chain` never checks a root's
  own self-signature, only intermediates/leaves against the root's public key.)
- **QEMU**: booting Aurora and running `httpsget` prints
  `(trust store: 8 roots)` with no parse failure, and the full 14.x.7
  `tools/securehttps_qemu.py` regression (RSA/P-256/P-384 controlled chains,
  validation ON) still passes 3/3 — the new roots add no regression to the
  existing depth-N path-building/CertificateVerify/hostname logic.

No private keys involved (these are public root certificates); nothing in the
PKI/TLS engine changed — 15.1 is data-only.

## Step 15.2 — HTTP redirects

`httpsget` followed exactly one URL (argv) and stopped. 15.2 makes it follow
301/302/303/307/308 redirects the way a browser does: **a redirect is a new
transaction**, not a continuation of the old one. Every hop gets a fresh DNS
lookup, a fresh TCP connect, and — since the scheme can change — either a fresh
TLS 1.3 handshake (with full certificate validation against the same trust
store) or a plain HTTP request, then a fresh GET. No TLS session, connection,
or buffer is reused across hops. This is deliberately the simple option: full
restart is easier to reason about and to get right than threading session
state through a scheme/host/port change, and it doesn't foreclose keep-alive
or session resumption later (delivered as 15.4 and 15.7 respectively) — those
are additive on top of this shape, not a rewrite of it.

Two new pieces:

- **`user/url.c`/`url.h`** — absolute-URL parsing and RFC 3986 §5.3 reference
  resolution: a `Location:` value can be an absolute URI, a network-path
  reference (`//host/path`), an absolute-path reference (`/path`), a
  query-only reference (`?q=1`), or a relative-path reference (`next`,
  `../next`), and each is resolved against the URL the response came from.
  Relative and absolute-path references get RFC 3986 §5.2.4 dot-segment
  removal (`/a/b/../c` → `/a/c`), with excess `..` at the root silently
  dropped rather than erroring (the same forgiving behavior browsers use).
  Freestanding like `x509/` and `tls/` — no libc, fixed-size buffers, no
  allocation — so the same object links into `httpsget.elf` and a host test
  binary unchanged.
- **`httpsget.c` restructuring** — the old single-shot `main()` body (TCP
  connect → TLS handshake → GET → read) became `do_fetch()`, callable once per
  hop against a `struct url`; `main()` now drives a redirect loop around it.
  The redirect controller: a hard `MAX_REDIRECTS` (20) ceiling, plus a
  visited-URL list checked before every hop so a cycle is reported as
  "redirect loop detected" immediately rather than silently spending the
  whole hop budget. Only 301/302/303/307/308 are followed (these are the
  status codes the read flow already in use — a no-body GET — handles
  identically; method-switching logic from the spec's finer distinctions
  doesn't apply since `httpsget` never sends anything but GET).

Verified two ways:
- **Host (`make url-test`)**: 31 cases against `url_parse`/`url_resolve` —
  absolute URLs (default/explicit ports, query, fragment-stripping,
  case-insensitive scheme, rejection of malformed input), and every
  RFC 3986 §5.3 reference kind including dot-segment collapsing, scheme/host/
  port changes, and an oversized-path case that must fail cleanly rather than
  overflow a fixed buffer.
- **QEMU (`tools/redirects_qemu.py`)**: three fresh-boot scenarios against a
  local `openssl s_server -HTTP` (raw canned HTTP responses — `-www`/`-WWW`
  always force a "200 ok" status line and can't produce a redirect) plus a
  small raw-socket plain-HTTP responder for the cross-scheme hop:
  1. same-host HTTPS→HTTPS redirect (301, absolute-path Location) → 200
  2. cross-scheme HTTPS→HTTP redirect (302, absolute-URI Location) → 200 —
     proving the plain-HTTP transport branch and the scheme/port switch run
     for real in the freestanding environment, not just in the host unit test
  3. a two-hop redirect cycle → "redirect loop detected"

  All 3/3 PASS, and the pre-existing 14.x.7 regression (RSA/P-256/P-384
  controlled chains, validation ON) still passes 3/3 unchanged — the
  `do_fetch` refactor didn't disturb the existing single-hop path.

## Step 15.3 — DHCP

Every IP address, gateway and DNS server in the stack was a compile-time
constant matching QEMU SLIRP's defaults (`10.0.2.15`/`10.0.2.2`/`10.0.2.3`).
15.3 makes them a runtime lease: a real RFC 2131 DISCOVER → OFFER → REQUEST →
ACK exchange against whatever DHCP server is actually on the wire, with T1/T2
renewal for as long as the lease lives and a safe fallback to the static
defaults on timeout, NAK, or lease loss.

Two new pieces:

- **`net/netcfg.c`/`netcfg.h`** — `struct net_config { ip, mask, gateway,
  dns[2] }`, one global instance, seeded with the static SLIRP defaults by
  `net_init()` before anything else runs. `net/inet.h`'s `IP_LOCAL`/
  `IP_GATEWAY` macros now read `g_net_config.{ip,gateway}` instead of
  expanding to a constant — every consumer (`arp.c`, `ipv4.c`, `tcp.c`,
  `net.c`) keeps using the same macro names and needed *zero* changes beyond
  that header. `dns.c`'s `IP_DNS` and `ipv4.c`'s subnet-mask check
  (`next_hop()`) were the only two call sites that referenced a value
  `net_config` doesn't expose through those macros, so they read
  `g_net_config.dns[0]`/`.mask` directly. The result matches the architecture
  asked for: static config, a DHCP lease, and a future GUI settings panel
  differ only in who calls `netcfg_set()`, never in the stack itself.
- **`net/dhcp.c`/`dhcp.h`** — the client itself, split the same way `dns.c` is
  (pure packet build/parse vs. the live transaction):
  - `dhcp_build_discover`/`dhcp_build_request`/`dhcp_parse_reply` are pure
    functions over byte buffers (RFC 2131 fig. 1 header + RFC 2132 TLV
    options: subnet mask, router, DNS, lease time, server identifier).
    `dhcp_build_request`'s `ciaddr` parameter selects the RFC 2131 state:
    zero means SELECTING (options 50/54 state the offer explicitly,
    broadcast flag set, since we have no usable address yet to receive a
    unicast reply); nonzero means RENEWING/REBINDING (ciaddr states the held
    lease directly, options 50/54 are omitted per §4.3.6).
  - `dhcp_configure(timeout_ms)` drives the SELECTING handshake, blocking and
    pumping `net_poll()` exactly like `dns_query()` already does — same
    idiom, new protocol. On ACK it calls `netcfg_set()`; on any failure
    `g_net_config` is untouched (the static seed from `net_init()` survives).
  - `dhcp_tick()`, called from `net_poll()` (same place `tcp_tick()` already
    runs), checks `dhcp_lease_due()` — a pure function of wall time, the same
    test-without-waiting idea as `arp_test_expire_all()` — and fires one
    renewal attempt per T1/T2 window: a unicast REQUEST to the leasing server
    at T1, a broadcast REQUEST at T2 if T1 never got an answer, and a fall
    back to `netcfg_reset_static()` at lease expiry if neither did. It must
    never call `net_poll()` itself (it runs *inside* `net_poll()`), so
    renewal is asynchronous: the request goes out immediately, the ACK/NAK is
    picked up opportunistically on a later tick via the same UDP handler
    `dhcp_configure()` uses. This is a deliberate simplification of RFC
    2131's full per-state retransmission schedule — one attempt per
    threshold, not a retry timer — sufficient for "lease storage + T1/T2 +
    renewal + fallback" without adding retry-timing complexity that isn't
    separately verifiable here.

  Two small additions outside `dhcp.c` make broadcast actually work:
  `ipv4_input()` now accepts `dst == 255.255.255.255` in addition to
  `dst == IP_LOCAL` (a DHCP reply is broadcast back since we have no unicast-
  reachable address yet), and `ipv4_send()` sends straight to the Ethernet
  broadcast MAC — no ARP — when the destination is the limited broadcast
  address (ARP-ing `255.255.255.255` would never get an answer).
  `kernel/kmain.c` calls `dhcp_configure(3000)` right after `net_init()`,
  before anything else touches the network; a `nodhcp` cmdline word skips it
  outright for static-only boots.

Verified two ways:
- **Host (`make dhcp-test`)**: 47 cases against the pure functions — DISCOVER/
  REQUEST(SELECTING)/REQUEST(RENEWING) packet shape (op/htype/xid/broadcast
  flag/ciaddr/chaddr/magic cookie/options), OFFER/ACK/NAK parsing (every
  option, including a two-DNS-server reply), seven rejection paths (wrong
  xid, wrong chaddr, wrong op, bad magic cookie, truncated, missing message-
  type option), and the full T1/RENEW → T2/REBIND → EXPIRED timeline from
  `dhcp_lease_due()`. `net/netcfg.c` is linked for real (it's pure); the
  handful of hardware-touching calls (`udp_*`/`net_poll`/`net_now_ms`/
  `virtio_net_*`/`kprintf`) are test doubles, since nothing here calls the
  live transaction — that path is QEMU-only.
- **QEMU (`tools/dhcp_qemu.py`)**, against SLIRP's own built-in DHCP server
  (no host-side DHCP server needed):
  1. default subnet (`10.0.2.0/24`) — the leased config comes out
     byte-identical to the static fallback, proving 15.3 is a drop-in: no
     other phase's behavior changes when DHCP is just confirming what was
     already hardcoded.
  2. a **different** subnet (`192.168.77.0/24`, set via `-netdev
     user,...,net=...`) — Aurora leases `192.168.77.15/24`, gateway
     `192.168.77.2`, DNS `192.168.77.3`, none of which exist anywhere in the
     source, and `nettest`'s gateway ping (4/4 replies) proves the leased
     address is actually wired into ARP/IPv4, not just printed.
  3. `nodhcp` on the cmdline — no DISCOVER is sent; the boot logs "skipped"
     and stays on the static config.

  All 3/3 PASS, and both the 14.x.7 (RSA/P-256/P-384) and 15.2 (redirects)
  QEMU regressions still pass 3/3 + 3/3 unchanged.

## Step 15.4 — HTTP keep-alive

Every request so far — the original single fetch, and every redirect hop —
paid for a fresh DNS lookup, TCP handshake and TLS 1.3 handshake. 15.4's goal
is narrow on purpose: skip that cost when the server says we don't need it,
nothing more. Not pipelining, not concurrent requests, not a connection pool,
not a persistent DNS cache — those are a different, later kind of feature.

Three pieces:

- **The HTTP parser** (`user/libc/http.c`, shared with Aurora Fetch) now
  determines `http_minor` (HTTP/1.0 vs 1.1), `chunked`, and a derived
  `keep_alive` verdict: HTTP/1.1 defaults to keep-alive unless the server
  says `Connection: close`; HTTP/1.0 defaults to close unless it says
  `Connection: keep-alive`. Either way, a body without a determinate length
  (no `Content-Length`, or chunked) can only be known to have ended when the
  connection closes — which defeats reuse regardless of what `Connection:`
  says — so `keep_alive` is false whenever that's the case.
- **`httpsget`'s session API** — `fetch_begin()`/`fetch_request()`/
  `fetch_end()`, replacing the old one-shot `do_fetch()`: `fetch_begin()`
  opens a connection (and does the TLS handshake, if any); `fetch_request()`
  sends one GET and reads the response on whatever's already open;
  `fetch_end()` closes it. `httpsget` always asks for keep-alive on its own
  requests (there's no cost to asking, and — following redirects — it can't
  know in advance whether the next hop will even be the same origin); a
  `reusable()` check on each *response* (keep-alive, determinate length, and
  no bigger than 64 KiB — not worth draining a huge body just to save one
  handshake) decides whether the caller keeps the session open. The CLI grew
  multiple paths (`httpsget host /a /b /c`) precisely to give this something
  to reuse across; the same reuse logic also fires when a redirect (15.2)
  lands on the same scheme/host/port as the response it came from.
- **Reading a response now has to know where it ends, not just when the
  peer stops talking.** Every phase before this one read until the g_resp
  preview buffer filled or the peer closed — safe, because `httpsget` always
  sent `Connection: close` itself, so the peer always closed. With
  keep-alive that assumption is gone: a response has to be drained to
  *exactly* `header_len + Content-Length` before the connection is safe to
  reuse (chunked bodies are simply never treated as reuse-eligible, so no
  incremental chunk-boundary tracking is needed at all). `resp_feed()`/
  `resp_done()` track this across however many read/decrypt calls it takes,
  and copy only up to the preview cap into `g_resp` regardless of how far
  past it the real body goes — the preview stays small, but the socket
  position always lands exactly on the next response's first byte.

  Reuse is optimistic, not verified in advance: Aurora has no non-blocking
  way to check a socket's liveness (`poll()` isn't wired to TCP sockets, and
  `read()` has no non-blocking mode — either would be needed to peek without
  risking a real wait). So the next request is just sent on the kept-open
  socket; if that write fails, or the read that follows it returns nothing
  at all, the connection is assumed dead and dropped, and *one* fresh
  reconnect is tried — no attempt to resurrect it, matching the "не
  пытаться реанимировать" scope from the outset.

  One bug worth naming because it's an easy one to reintroduce: the reuse
  decision must compare only scheme/host/port (`same_origin()`), not the
  full URL. Reusing `url_eq()` (built for redirect-loop detection, which
  correctly does care about the whole URL) here at first meant every
  request looked like "a different origin" purely because its *path*
  differed, forcing a fresh handshake every time — the opposite of the
  feature. The QEMU test below caught it immediately (zero "reusing" lines
  where there should have been two).

Verified with `tools/keepalive_qemu.py`, against a small persistent-
connection TLS server written for this test (`openssl s_server -HTTP`/`-WWW`
was checked by hand first and always closes after exactly one request
regardless of `Connection:`, so it can't serve this scenario; a plain Python
`ssl`-based server works with no special cipher/group setup, because
Aurora's ClientHello offers exactly one cipher suite and one group, so any
compliant TLS 1.3 server converges on them regardless of its own preference
order):
1. three paths, every response `Connection: keep-alive` — exactly one
   handshake serves all three ("reusing open connection" appears twice).
2. the first response says `Connection: close` — the next path gets a
   second, fresh handshake, no reuse attempted.
3. the first response says `keep-alive` but the server drops the connection
   anyway (a realistic short-idle-timeout race) — the optimistic reuse's
   write/read fails, `httpsget` logs "already closed -- reconnecting", and
   completes the second request over a fresh connection.

All 3/3 PASS, and the 14.x.7, 15.2 and 15.3 QEMU regressions all still pass
unchanged. (Incidentally, running the full suite this far into a long
session also caught a latent, unrelated test-harness bug: `HTTPSGET_NOW` is
a fixed compile-time constant, and `securehttps_qemu.py`/`redirects_qemu.py`
generate certs with `notBefore` = whenever openssl actually runs, so enough
elapsed real time within the same calendar day made the constant drift
behind the certs' validity window, failing with "leaf not yet valid" — a
timing artifact of the *harness*, not a regression. Both scripts now pass
the live clock as httpsget's optional numeric override instead of relying
on the default.)

## Step 15.5 — trust store: toward a real browser-bundle approximation

15.1 added 3 ECDSA roots for a total of 8. 15.5's target is different in kind,
not just size: go from "a curated handful" to "a first real approximation of
what a browser ships" — the ~20-40 root organizations that between them issue
most of the certificates the web actually uses — while explicitly not chasing
Mozilla's full multi-hundred-root bundle, CRL/OCSP revocation, or trust
policies (constraints, not a browser). The store grew from 8 roots (5 issuer
orgs: Let's Encrypt, DigiCert, Sectigo, Google) to **21 roots across 9 issuer
orgs**, adding GlobalSign, Amazon Trust Services, Microsoft, and Entrust, plus
more roots from the orgs already present (DigiCert Global Root G3/Trusted
Root G4/High Assurance EV, GTS already had 4). Every new root was fetched
directly from its issuer's own certificate repository (`cacerts.digicert.com`,
`secure.globalsign.com`, `amazontrust.com`, `microsoft.com/pkiops`,
`files.entrust.com`) — the same standard this project held itself to for the
original 8, never a third-party bundle.

Two new pieces:

- **`tools/gen_ca_roots.py`** — the trust store stopped being a hand-edited
  byte array. The generator reads every PEM in `tools/trust_roots/` (the 8
  original roots are re-derived from the old `user/ca_roots.h`'s exact bytes,
  now checked in as PEM instead of only existing as an opaque C array — see
  the byte-identity proof below), rejects anything that isn't self-issued,
  isn't `basicConstraints CA:TRUE`, or isn't RSA/ECDSA-P256/ECDSA-P384 (the
  only public-key types Aurora's crypto stack implements — a P-521 or Ed25519
  root would be silently useless as a trust anchor, so it's refused outright
  rather than included), and writes `user/ca_roots.h` in the exact format the
  file already used. Updating the store is now: drop a new cert's PEM into
  `tools/trust_roots/`, re-run the script, commit the diff — the same
  generated-source pattern `kernel/embedded_user.c` already established, not
  a new idea.
- **`tools/ca_roots_test.c`** (`make ca-roots-test`) — parses every root with
  Aurora's own x509 parser, reports the RSA/EC P-256/EC P-384 breakdown, and
  self-verifies each one with Aurora's own crypto against its own real
  production DER (the 15.1 proof technique, now covering the whole store: 14
  of 21 verify OK, 7 report `UNSUPPORTED` for a legacy SHA-1 or unimplemented
  RSA-hash self-signature — pre-existing, irrelevant to trust, since
  `x509_verify_chain` never checks a root's own signature). A coverage floor
  (≥20 roots, ≥10 RSA, ≥1 EC P-256, ≥5 EC P-384) catches a future update that
  silently drops a whole key-type family. It also checks one **real chain
  link**: `GTS CA 1C3`, Google's actual production intermediate (fetched from
  `https://pki.goog/repo/certs/gts1c3.pem`), genuinely signed by `GTS Root
  R1` — verified with `x509_verify_signature` against the root's real public
  key, not a synthetic vector. A live leaf certificate from a real site
  (github.com, cloudflare.com, ...) turned out not to be capturable from this
  sandbox: its outbound HTTPS is intercepted by a TLS-inspecting egress proxy
  (the same one `tls-live-test`'s `AURORA_TRUST_PEM` already works around), so
  `openssl s_client -showcerts` against a real site shows the *proxy's*
  certificate, not the origin's. A CA's own published intermediate is the
  closest available substitute: still real, CA-issued, independently-keyed
  material, fetched the same trustworthy way the roots themselves were.

Verified:
- **Host (`make ca-roots-test`)**: all of the above — 21/21 parse, the
  RSA/EC breakdown and coverage floor, self-signature checks, and the real
  GTS Root R1 → GTS CA 1C3 link. All pass.
- **Byte-identity for the original 8**: before committing, every one of the
  8 pre-15.5 roots' DER was diffed byte-for-byte between the old hand-written
  `user/ca_roots.h` and the newly generated one (PEM round-tripped through
  `tools/trust_roots/`) — all 8 matched exactly, so 15.5 is additive: nothing
  that worked before changes.
- **QEMU**: booting Aurora and running `httpsget` prints
  `(trust store: 21 roots)` with no parse failure inside the real
  freestanding i686 environment. The 14.x.7, 15.2, 15.3 and 15.4 QEMU
  regressions (RSA/P-256/P-384 chains, redirects, DHCP, keep-alive) all still
  pass unchanged — 21 roots is a superset of the 8 those tests' own temporary
  test-root substitution never even touches.

## Step 15.6 — DNS cache

Every DNS-driven connection re-resolved the name from scratch: a redirect to
a different host, or simply running `httpsget` again a moment later, always
paid for a fresh query + UDP round trip, even for a name just looked up.
15.6 adds a cache to `net/dns.c` itself, so every existing caller
(`tcpsock_connect`, `net_http_get`, `net_selftest`) benefits with no changes
of its own — `dns_query()` checks the cache first and populates it after a
real query, transparently.

Two kinds of entry, matching what a real resolver does:
- **Positive** — the resolved address, cached for the answer's own TTL
  (parsed off the wire; `parse_response()` previously ignored it entirely),
  clamped to [5 s, 1 h] so neither a near-zero TTL (query storms) nor a huge
  one (an effectively-permanent stale answer) can happen. A TTL of exactly 0
  means "do not cache this answer" (RFC 1035) and is honored as such.
- **Negative** — a failed lookup (timeout, no matching record) is cached too,
  for a fixed 10 s, so a redirect chain or retry loop touching an unreachable
  or misspelled host doesn't re-pay the full query timeout on every attempt.

The cache logic itself (`dns_cache_find`/`dns_cache_slot_for`/
`dns_cache_put_positive`/`dns_cache_put_negative`, plus TTL clamping and
case-insensitive name comparison per RFC 4343) is pure — parametrized on an
explicit `now_ms` rather than reading the clock, the same idea 15.3's
`dhcp_lease_due()` used — so it's host-testable without a network or time
stub, and eviction is the same lazy-expiry-plus-soonest-to-expire-victim
policy `net/arp.c`'s cache already established.

Verified two ways:
- **Host (`make dns-cache-test`)**: 27 cases — name equality, TTL clamping
  at both bounds, a cache miss on an empty cache, a hit immediately after
  storing (case-insensitive), lazy expiry exactly at the TTL boundary,
  negative entries and their (shorter) expiry, and the slot-allocation
  policy under a full cache: refreshing an existing name reuses its own
  slot without disturbing others, and a genuinely new name evicts the
  soonest-to-expire entry.
- **QEMU (`tools/dns_cache_qemu.py`)**, against the real SLIRP-forwarded
  resolver (no synthetic DNS server): `net_selftest()` now re-queries
  "example.com" right after its existing first lookup — the second call
  logs `[dns] cache hit: example.com -> ...` and returns the identical
  address, not a second round trip — and queries a deliberately
  unresolvable name twice, the second logging `[dns] cache hit (negative)`.
  Both PASS, and the 14.x.7, 15.2, 15.3 and 15.4 QEMU regressions are
  unaffected (none of them exercise hostname-based DNS resolution; they
  all target `10.0.2.2` directly as an IP literal, which skips DNS
  entirely — see `net/tcpsock.c`'s `parse_ipv4` fast path).

## Step 15.7 — TLS 1.3 session resumption

Even with 15.4's keep-alive and 15.6's DNS cache, a *new* connection to an
origin Aurora had already talked to still paid for a full TLS 1.3 handshake:
a fresh ECDHE exchange, a full certificate chain sent and verified, and a
CertificateVerify signature checked — the most expensive part of the whole
stack. 15.7 lets a second connection to the same origin skip all of that,
the same way a browser does: cache the session ticket the server hands out
after the first handshake, and offer it as a PSK on the next one.

The key-schedule math (RFC 8446 §7.1) is structurally the same for a
resumed handshake as a full one — Early Secret → Handshake Secret → Master
Secret, via the same `Derive-Secret`/`HKDF-Expand-Label` chain — with one
difference: Early Secret is `HKDF-Extract(0, PSK)` instead of
`HKDF-Extract(0, 0)`. `tls_key_schedule_derive_from_early()` is the existing
schedule taking that Early Secret as a parameter; the pre-15.7
`tls_key_schedule_derive()` becomes a one-line wrapper around it for
PSK = 0, so every one of its ~12 existing call sites is untouched.

Four new pieces, `tls/session.h`'s `tls_session_ticket` (ticket bytes, PSK,
lifetime, and when it was obtained) threading through all of them:

- **`tls/key_schedule.c`** — `tls_derive_early_secret()` (PSK or all-zero),
  `tls_derive_binder_key()`, `tls_derive_resumption_master_secret()` (from
  `Transcript(ClientHello..client Finished)`, computed once a handshake
  reaches CONNECTED — RFC 8446 §7.1), and `tls_derive_ticket_psk()` (a
  ticket's actual PSK, `HKDF-Expand-Label(resumption_master_secret,
  "resumption", ticket_nonce)` — RFC 8446 §4.6.1).
- **`tls/handshake.c`** — `tls_build_client_hello()` now optionally appends
  `psk_key_exchange_modes` (`psk_dhe_ke` only — a resumed connection still
  does a fresh ECDHE exchange, keeping forward secrecy even under PSK) and
  `pre_shared_key`, which per RFC 8446 §4.2.11 must be the last extension
  and carries a **binder**: an HMAC over the entire ClientHello up to but
  excluding the binders list itself, computed by writing every length field
  as if the binder were already present, hashing that prefix, then patching
  the real HMAC in afterward. Getting the exact byte boundary right is a
  well-known place to go subtly wrong; it was derived here by diffing RFC
  8448 §4's own 477-byte "prefix" against its 512-byte final ClientHello
  (exactly 35 bytes apart — the whole binders-list structure, length prefix
  included) before writing a line of production code.
  `tls_parse_server_hello()` gained an optional `psk_selected` output (the
  server's `pre_shared_key` extension carries only a `selected_identity`
  index; since Aurora only ever offers one identity, its mere presence means
  "accepted"). `tls_parse_new_session_ticket()` parses the post-handshake
  `NewSessionTicket` message (RFC 8446 §4.6.1) Aurora previously discarded
  outright.
- **`tls/client.c`** (the FSM) — `tls_client_offer_psk()` (called after
  `tls_client_init`, before `tls_client_start`) computes the PSK-based Early
  Secret and binder key up front. At `WAIT_SH`, if the server's ServerHello
  selected the PSK, the FSM sets `psk_accepted` and runs the key schedule
  from the PSK-based Early Secret instead of the zero one — otherwise it's a
  silently full handshake (RFC 8446 §4.1.4's fallback rule needs no explicit
  code: the zero-Early-Secret path *is* the existing full-handshake
  behavior). The one real branch: at `WAIT_EE`, a resumed handshake jumps
  straight to `WAIT_FINISHED`, skipping `WAIT_CERT`/`WAIT_CV` — PSK
  possession, proved by a valid Finished, is itself the authentication (RFC
  8446 §2.2), so `peer_authenticated` is set there instead of after a
  CertificateVerify. Once CONNECTED, the resumption master secret is
  derived and cached on the FSM for whatever ticket arrives next.
- **`tls/conn.c`** — the post-handshake `NewSessionTicket` case (previously
  `return TLS_CONN_OK` and nothing else) now parses the ticket, derives its
  PSK from the FSM's resumption master secret, and stashes it for
  `tls_conn_take_ticket()` to collect. `tls/` has no clock, so
  `obtained_ms` comes back 0 from `tls_conn_take_ticket()` — the caller
  (`httpsget`) stamps its own current time before ever offering the ticket.

**`user/httpsget.c`** ties it together with a small in-process cache (one
slot per host:port, holding only the most recent ticket): `fetch_begin()`
offers a cached, unexpired ticket via `tls_conn_offer_psk()` before the
handshake; the read loop in `fetch_request()` captures any ticket that
arrives via `tls_conn_take_ticket()`, on any connection. (The lifetime
check compares in the millisecond domain via multiplication rather than
dividing `uint64_t` values down to seconds — this is freestanding i686 code
with no libgcc, and 64-bit division needs `__udivdi3`, which doesn't exist
here; 64-bit multiplication needs no library call and is fine.) The cache
lives only for one process's lifetime — there's no persistence across
separate `httpsget` invocations — so it pays off within a single run that
touches an origin more than once: a redirect back to an earlier host, or,
as in the acceptance test below, a `Connection: close` response forcing a
second connection to the same origin.

Verified two ways:
- **Host (`make tls-trace-test`)**: RFC 8448 §4's own published PSK, Early
  Secret, binder key, finished key, binder, and resumption master secret
  values, checked byte-exact against Aurora's derivation functions (the RFC
  8448 §4 ClientHello itself is 0-RTT-capable and so can't be byte-replayed
  against a client that deliberately doesn't implement 0-RTT — see below —
  but the underlying key-schedule math is identical either way). A second,
  synthetic FSM-level test then drives an actual resumed handshake through
  `tls_client_offer_psk()`/`tls_client_start()`/`tls_client_recv_handshake()`
  using that RFC-verified PSK: the produced ClientHello carries both PSK
  extensions and a binder that independently re-verifies; a PSK-accepting
  ServerHello is accepted, `WAIT_CERT`/`WAIT_CV` are skipped entirely, and
  the handshake reaches CONNECTED with `peer_authenticated` set and a fresh
  resumption master secret ready for the next ticket.
- **QEMU (`tools/tls_resume_qemu.py`)**, against a real TLS 1.3 server
  (Python's `ssl` module, i.e. OpenSSL — not a simulated PSK accept):
  `httpsget 10.0.2.2 /a /b` forces two separate connections (`/a` answers
  `Connection: close`), so the first is necessarily a full handshake and the
  second gets to try resumption using the ticket cached from the first.
  Confirmed genuinely accepted, not a silent fallback, by two independent
  witnesses: the client-side trace shows "PSK accepted -- resuming" only on
  the second connection, and — the authoritative check — the server's own
  `SSL_session_reused()` (verified beforehand, locally, to read correctly
  for TLS 1.3 server sockets) reports exactly `[False, True]`. All 8 checks
  pass, and the 14.x.7, 15.2, 15.3 and 15.4 QEMU regressions are unaffected.

Deliberately out of scope, matching what was asked for: 0-RTT early data (no
`early_data` extension, no early traffic keys — replay-safety for 0-RTT is a
meaningfully harder problem than 1-RTT PSK resumption and wasn't part of the
goal here), a connection pool, a cookie jar, and HTTP compression — later,
separate features.

## Step 15.10 — gzip / DEFLATE decompression

Every response so far arrived exactly as the server's HTML/JSON/whatever
actually is, byte for byte — but virtually every real server on the modern
web sends `Content-Encoding: gzip` by default, shrinking a typical page 3-10x.
Without decoding it, `httpsget` would either show garbage (the raw compressed
bytes) or have to ask servers not to compress at all, both worse than doing
the decompression itself. Unlike 15.7, this needed no existing library to
lean on — DEFLATE (RFC 1951) and its gzip container (RFC 1952) are built from
scratch, at the same rigor as the hand-rolled crypto: real compressed streams
as test vectors, not just self-consistency.

The one requirement worth calling out on its own: decompression had to be
**genuinely incremental** — a caller feeds compressed bytes as they arrive
off the wire and pulls decompressed bytes into whatever output buffer it
currently has room for, so neither the whole compressed input nor the whole
decompressed output ever has to sit in memory at once. This ruled out the
obvious shortcut (buffer the whole response, decompress it in one call) and
meant the DEFLATE state machine has to be resumable at literally every step —
mid-Huffman-code, mid-back-reference-copy, mid-header-field.

Three new pieces, in `compress/` (a new top-level tree alongside `crypto/`,
`tls/`, `x509/` — same freestanding discipline: only `<stdint.h>`/
`<stddef.h>`, no allocation):

- **`compress/crc32.c`** — the reflected CRC-32 gzip's trailer uses to catch
  corruption, pinned against the standard check value (`CRC32("123456789")
  == 0xCBF43926`).
- **`compress/inflate.c`** — the DEFLATE decoder itself (RFC 1951). The
  canonical-Huffman table construction and bit-at-a-time symbol decode follow
  the well-known structure of Mark Adler's public-domain `puff.c` (the zlib
  author's own minimal reference decoder) — but restructured throughout into
  an explicit state machine (`inflate_mode`) so every step can pause on
  "need more input" or "output buffer full" and resume exactly where it left
  off, which a whole-buffer-at-once reference decoder like `puff.c` never
  needs to do. Stored, fixed-Huffman, and dynamic-Huffman blocks are all
  supported; LZ77 back-references are resolved through a 32 KiB sliding
  window that also doubles as the record of everything already delivered to
  the caller, since a back-reference can point at output produced in an
  earlier `inflate_feed()` call.
- **`compress/gzip.c`** — the gzip container format (RFC 1952) wrapping
  `inflate.c`: the fixed 10-byte header, the optional FEXTRA/FNAME/FCOMMENT/
  FHCRC fields (parsed and skipped correctly, not just assumed absent), the
  compressed body, and the CRC32+ISIZE trailer, verified against what was
  actually decompressed. Just as incremental as `inflate.c` itself — the
  header, body, and trailer can each arrive split across arbitrarily many
  `gzip_feed()` calls.

**`httpsget`** sends `Accept-Encoding: gzip` on every request and, when a
response says `Content-Encoding: gzip`, decompresses it as wire bytes arrive
in `resp_feed()` — not after buffering the whole compressed body, and not
only at display time. A response that's *both* chunked and gzip-encoded
(legal, but rare) falls back to a one-shot dechunk-then-gunzip pass at
display time instead, since `dechunk()` itself has never been incremental
either — that narrower combination was never going to be truly streaming
regardless of what gzip.c can do on its own.

One real bug worth naming, caught immediately by the QEMU acceptance test
below (a page fault, not a wrong answer, so impossible to miss): the first
version of the chunked+gzip fallback declared its `gzip_ctx` as a plain
local variable. `gzip_ctx` embeds `inflate_ctx`'s 32 KiB sliding window, and
C reserves a function's entire stack frame at entry regardless of which
branch actually runs — so merely *having* that declaration inside `fetch_
one()`, even inside a rarely-taken `if`, blew straight through Aurora's
16 KiB (`USTACK_PAGES = 4`) user stack on the very first call, before any
networking even happened. Fixed by making it `static`, exactly like the
sibling scratch buffers right next to it.

Verified two ways:
- **Host**: `make crc32-test` (the standard check value plus streaming/
  one-shot equivalence); `make inflate-test` (six real raw-deflate streams
  from Python's `zlib`, chosen to force every block type at least once,
  including a 40 KB stream whose back-references force the 32 KiB window to
  wrap and still resolve correctly, plus a corrupted-stream rejection check
  and a dedicated streaming test feeding the same bytes through 1-3-byte
  input chunks and a 7-byte output buffer — proving the incremental design
  is real, not buffer-then-decompress in disguise); `make gzip-test` (four
  real gzip streams from Python's `gzip` module, including one with
  `FLG.FNAME` set, plus bad-magic/bad-CM/tampered-CRC32 rejection checks and
  its own chunk-boundary streaming test). All constants in these three test
  files were generated and written directly into place by a Python script —
  a multi-hundred-byte array is exactly the kind of thing that's easy to
  mistype by hand and see the resulting failure blamed on the decoder
  instead, which happened twice while drafting these vectors before this
  discipline was applied.
- **QEMU (`tools/gzip_qemu.py`)**, against a real TLS 1.3 server (Python's
  `ssl` module): the server inspects the *actual* incoming request for
  `Accept-Encoding: gzip` (proving `httpsget` really sent it) and answers
  with genuinely gzip-compressed bytes; `httpsget` decompresses them to the
  original readable text, reporting the *decompressed* byte count, not the
  wire size. A second, uncompressed control response on the same run
  confirms the plain path still works unchanged. All 6 checks pass, and the
  14.x.7, 15.2, 15.3, 15.4 and 15.7 QEMU regressions are unaffected.

## Step 15.9 — cookie jar

gzip made pages smaller; this makes them actually *work*. Without cookies,
`httpsget` re-identifies itself as a brand-new visitor on every single
request — no login can survive a redirect, no consent flow can complete, no
session can persist across a second path in the same run. Every response's
`Set-Cookie` headers were simply discarded until now.

**`user/cookiejar.c`** is a compact RFC 6265 implementation — freestanding,
no libc, no allocation, same discipline as `url.c` — built around a
fixed-size array of 32 entries with LRU eviction, deliberately not the
full spec: Domain, Path, Expires, Max-Age, Secure and HttpOnly are
implemented; SameSite, Priority, Partitioned and the rest are parsed as
"unknown attribute" and silently ignored, since none of them are load-
bearing for a plain HTTPS client with no scripting layer to protect.

A few pieces worth calling out:

- **Domain/Path scoping is enforced in both directions.** Setting a cookie
  with an explicit `Domain` attribute that the request host doesn't
  domain-match (RFC 6265 §5.1.3) gets the *whole cookie* rejected — a
  server can't plant a cookie for a domain it doesn't control. Sending one
  back applies the same domain-match check plus `Path` prefix-matching
  (§5.1.4, including the "default-path" derivation when `Path` is absent),
  so a cookie scoped to `/admin` is never sent to `/profile` just because
  the jar happens to hold it.
- **Max-Age beats Expires when both are present** (§5.3), and either one
  landing at or before the current time is treated as a deletion request,
  not a zero-length lifetime — that's how a server actually asks a client
  to forget a cookie. `Expires` itself is an HTTP-date, parsed with a
  tolerant token scan (pull the first bare integer as the day, the first
  3+ letter word as the month, the next bare integer as the year, HH:MM:SS
  wherever it appears) rather than a fixed-format parser, so the RFC 1123
  shape virtually every real server emits parses correctly without
  demanding exact placement.
- **LRU, not FIFO, eviction.** When the jar is full, the entry evicted is
  whichever one hasn't been touched (set *or* sent) most recently — a
  cookie a page keeps actually using survives even if 31 others were set
  around the same time and never touched again.
- **`httpsget` only reads `Set-Cookie` from the wire bytes it already had**
  (`g_resp`), via a new `http_find_header()` (`user/http.c`) that
  enumerates every occurrence of a repeatable header — `struct
  http_response`'s existing single-value fields have no way to represent
  "however many Set-Cookie headers this response happened to send," and
  deliberately wasn't grown to try, for a reason the next paragraph makes
  concrete.

One near-repeat of 15.10's stack lesson, caught before it shipped rather
than after: the natural-looking place to store parsed cookie data would
have been inside `struct http_response` itself, alongside `location` and
`content_type`. But `fetch_result_t` (which embeds a `struct
http_response` by value) is a *stack-local* in `fetch_one()`, and 15.10 had
just shown exactly how a plain-looking local variable can blow Aurora's
16 KiB user stack. Keeping the cookie jar itself as a `static` global (like
the session-ticket cache) and reading `Set-Cookie` straight out of the
already-captured `g_resp` sidesteps the whole risk rather than budgeting
around it.

Verified two ways:
- **Host (`make cookiejar-test`)**: 30 cases spanning domain-match (exact,
  parent, sibling subdomain, leading-dot normalization, and rejecting an
  unrelated host), path-match (prefix with a real slash boundary vs. a
  bare shared-prefix false positive, and the default-path derivation from
  several request paths), Max-Age/Expires precedence and deletion,
  overwrite-on-same-(name,domain,path), Secure withholding over plain
  HTTP, and LRU eviction (filling all 32 slots, touching one, and
  confirming *that* one survives while the true least-recently-used one is
  evicted to make room for a new cookie).
- **QEMU (`tools/cookies_qemu.py`)**, against a real TLS 1.3 server:
  `/login` sets a `Path=/` session cookie and a `Path=/admin` cookie; the
  first request carries no cookies at all (the jar starts empty); a later
  `/profile` request sends the session cookie back but *not* the
  `/admin`-scoped one, and a later `/admin` request sends both — proving
  real RFC 6265 scoping, not "resend everything the jar has ever seen." All
  7 checks pass, and the 14.x.7, 15.2, 15.3, 15.4, 15.7 and 15.10 QEMU
  regressions are unaffected.

## Step 15.8 — multi-origin session cache

15.4 already kept one connection alive across several requests to the same
origin, and 15.7 already let a *new* connection to a previously-seen origin
skip a full handshake. What neither one covered: `fetch()`'s own reconnect
logic closed whatever was open the instant a request targeted a *different*
origin — so a redirect chain that bounced A → B → A paid for two full
round-trip costs to A even though the first connection to A might still
have been perfectly healthy. This step is explicitly named "multi-origin
session cache," not "connection pool": there is no concurrency here to pool
for, and no background thread, timer, or cleanup daemon — the whole client
remains exactly as synchronous as every phase before it.

**`user/httpsget.c`** replaces the single global `tls_conn`/
`tls_record_reader`/session-ticket-cache with `TLS_SESSION_SLOTS` (4)
`session_slot` entries, each independently able to hold a live, reusable
connection *and* a session ticket at the same time — the two survive on
different schedules now: a slot's connection closes the moment a response
on it isn't `reusable()` (exactly 15.4's existing rule), but its ticket
keeps living in the slot regardless, exactly as it did in 15.7's separate
cache. `slot_find_or_alloc()` looks a slot up by host+port, or binds a free
one, or — when every slot is already bound to a different origin — evicts
whichever origin's slot has gone longest untouched (closing its live
connection, forgetting its ticket). `fetch()` now reuses a found slot's
open connection first; only when there isn't one does it reconnect,
offering that slot's ticket if it has one.

One sizing note carried over directly from 15.10's postmortem, applied
proactively rather than rediscovered the hard way: `tls_conn` and
`tls_record_reader` are large (~37 KiB and ~33 KiB, mostly reassembly
buffers), so 4 of each is a genuinely sizeable chunk of memory (~280 KiB) —
entirely fine as a `static` global array, and never even considered as
anything else, precisely because 15.10 already demonstrated what a
plain-looking large *local* does to Aurora's 16 KiB user stack.

Verified against two real TLS 1.3 servers (Python's `ssl` module) on
different ports of the same host -- two distinct origins by definition,
with no DNS or multi-host setup needed:

- **`tools/session_cache_qemu.py`**: `httpsget 10.0.2.2 /starta` redirects
  to origin B's `:8443/hop` (a `Connection: keep-alive` response, so
  origin A's slot connection is deliberately left open), which redirects
  back to origin A's `:443/finish`. The log shows exactly one `TCP
  connected to 10.0.2.2:443` line and exactly one `TCP connected to
  10.0.2.2:8443` line — origin A is *never* reconnected — and the return
  to A is served via "reusing open connection," with no ClientHello, no
  handshake trace at all, between the reuse line and the response. All 6
  checks pass, and the full existing host + QEMU regression suite —
  including 15.7's own resumption test, whose ticket now lives inside a
  session slot instead of a separate cache — is unaffected.

This closes out the run of phases from 15.3 through 15.10: DHCP, DNS
caching, keep-alive, an expanded trust store, TLS session resumption,
gzip, a cookie jar, and now a multi-origin session cache, all layered onto
the 14.x HTTPS foundation without changing its shape. Taken together this
is worth calling **"Aurora HTTPS v2"** — a clear step up from the original
`docs/RELEASE-https-v1.md` milestone, still with no HTTP/2, no concurrency,
and no dependency beyond the freestanding TLS/X.509/crypto stack this
project has built from scratch throughout. HTTP/2, IPv6, WebSockets and
request bodies (POST/PUT) are deliberately not part of this milestone —
each is its own separate, later project.

## Step 16.1 — HTTP POST

The first step of a new series (`16.x`, "Web Platform") explicitly kept
separate from the `15.x` HTTPS v2 milestone: everything up to here could
only read the web. `httpsget` gains `--post <host> <path> <body>`, sending
`body` as `application/x-www-form-urlencoded` with an auto-computed
`Content-Length` — the one body shape this client's CLI can actually
construct, since Aurora's shell (`user/sh.c`) has no argument quoting, so
`body` has to be a single whitespace-free token.

The method and body apply to the very first request in a redirect chain;
what happens on any hop after that was, at this step, a fixed downgrade to
a bodyless GET, matching what browsers have done for 301/302/303 since long
before it was standardized (RFC 7231 codifies it as legacy behavior, and
recommends 307/308 for a server that actually wants the method and body
preserved across a redirect). That preservation wasn't implemented yet at
this step — a deliberate first-cut simplification, not an oversight, and
resolved two steps later in 16.3 without disturbing anything here.

Two small pieces, both inside `user/httpsget.c`:

- **`build_request()`** grew a `method` parameter (previously hardcoded to
  `"GET"`) and optional `body`/`bodylen` parameters: when present, it
  writes `Content-Type: application/x-www-form-urlencoded` and
  `Content-Length: <n>` before the blank line, then the raw body bytes
  after it, all into the same request buffer as the headers (a POST that
  size can't legitimately reach is out of scope for a diagnostic CLI, not
  a general-purpose uploader) — so `fetch_request()` still sends the whole
  request in the one write it always did.
- **Buffer sizing**: `POST_BODY_MAX` (4 KiB) caps how large a body this
  client will ever send, and the request buffer (`REQ_BUF_MAX`) and the
  outgoing-record scratch buffer (`g_scratch`) are both sized to comfortably
  hold headers + a full Cookie: line + the largest possible body in one
  TLS record (`TLS_RECORD_MAX_PLAINTEXT` is 16 KiB, so this never needs to
  span records). Both are still plain `static` globals — the same
  discipline 15.10's stack-overflow postmortem established and 15.8
  already applied proactively to the session-slot array.

Verified two ways:
- **Host**: the full existing suite (`make crypto-test` through
  `make cookiejar-test`) passes completely unchanged — the GET path
  through `build_request()`/`fetch_request()` is byte-identical when
  `body` is NULL.
- **QEMU (`tools/post_qemu.py`)**, against a real TLS 1.3 server:
  `httpsget --post 10.0.2.2 /submit name=alice&age=30` is checked from the
  *server's* side (not just httpsget's own "sent" log line) — the request
  really is a `POST`, really carries
  `Content-Type: application/x-www-form-urlencoded`, a `Content-Length`
  that matches the real body length, and the exact bytes
  `name=alice&age=30`. `/submit` then redirects to `/landing`, and that
  second request arrives as a bodyless `GET` with no `Content-Length` at
  all, confirming the documented downgrade actually happens on the wire.
  All 9 checks pass, and the full existing host + QEMU regression suite is
  unaffected.

## Step 16.2 — HTTP authentication (Basic + Bearer)

POST unlocked writing to the web; this unlocks talking to it as *someone*
-- the overwhelming majority of REST APIs (GitHub, GitLab, most SaaS and
LLM APIs) gate every request behind `Authorization: Bearer <token>`, and
plenty of older or internal services still use `Authorization: Basic
<base64(user:pass)>`. `httpsget` gains `--auth-basic user:pass` and
`--auth-bearer token` (mutually exclusive, combinable with `--post`), each
a single whitespace-free CLI token for the same reason POST's body is:
Aurora's shell has no argument quoting.

**`user/base64.c`** is a new small freestanding module (RFC 4648, standard
alphabet, encode-only -- httpsget never needs to decode base64) — nothing
in the codebase needed a base64 encoder before Basic auth did. It follows
the same discipline as `url.c` and `cookiejar.c`: only `<stddef.h>`/
`<stdint.h>`, no libc, no allocation, so it's host-testable standalone.

The one design point worth calling out: **the Authorization header is
re-evaluated on every redirect hop, not fixed at hop 0 like POST's body
is.** It's scoped to whichever origin (`https`/host/port) it was given
for (`g_auth_origin`, set once from the CLI's `<host>` argument) and
`fetch_one()` checks `same_origin()` against the *current* hop's URL on
every iteration -- so a same-origin redirect keeps sending it (useful:
plenty of APIs redirect `/v1/resource` to `/v1/resource/` and still expect
credentials), while a redirect to a *different* origin drops it
automatically. This is deliberately stricter than what some real HTTP
clients do by default (curl, for one, will follow a cross-host redirect
and keep sending `Authorization` unless told not to) — for a from-scratch
client with no prior behavior to stay compatible with, not leaking
credentials to an origin the caller never named is the safer default, not
a compatibility risk.

Verified two ways:
- **Host (`make base64-test`)**: RFC 4648 §10's own published test
  vectors (`""`, `"f"`, `"fo"`, ..., `"foobar"`, exercising all three
  padding cases) plus two realistic `"user:pass"` strings, plus a check
  that an undersized output buffer is rejected outright rather than
  silently truncated.
- **QEMU (`tools/auth_qemu.py`)**, against real TLS 1.3 servers, three
  scenarios: `--auth-basic alice:s3cr3t` is checked by having the server
  decode the base64 *itself* (Python's own `base64` module, not trusting
  httpsget's encoder) and confirming it decodes to exactly
  `"alice:s3cr3t"`; `--auth-bearer mytoken123` is checked against the
  exact header value `"Bearer mytoken123"`; and a third scenario proves
  the origin-scoping directly -- a Bearer token given for origin A arrives
  there intact, but origin B (reached via a redirect from A) receives no
  `Authorization` header at all. All 9 checks pass, and the full existing
  host + QEMU regression suite is unaffected.

## Step 16.3 — RFC-correct redirects for a request with a body

16.1 deliberately simplified redirect handling for a `POST`: any redirect
at all downgraded to a bodyless `GET` on the next hop, regardless of
status code. That's correct for 301/302/303 but wrong for 307 Temporary
Redirect and 308 Permanent Redirect, whose entire reason to exist in RFC
7231 §6.4.7 / RFC 7238 is preserving the method and body across the
redirect — and 307/308 are exactly what modern REST APIs and cloud
services tend to use for a redirected `POST`, so this wasn't a corner case
worth leaving unfixed.

The fix is entirely inside `fetch_one()`'s loop in `user/httpsget.c`: what
used to be `hop == 0 ? method : "GET"` (decided once, at the very start)
became three loop-local variables (`req_method`/`req_body`/`req_bodylen`)
that start at the original method/body and get re-decided *after every
redirect response*, based on that response's specific status code —
307/308 leave them untouched, anything else (301/302/303) resets them to
a bodyless GET. `build_request()` itself needed no changes at all: it
already recomputes `Content-Length` fresh from `bodylen` on every call, so
resending the same body on a 307/308 hop is just calling it again with the
same arguments.

One consequence worth naming because it's easy to get backwards: the
decision is **per-redirect, not sticky for the rest of the chain**. A
`POST` that survives two 307/308 hops in a row and then hits a plain 302
still downgrades to `GET` on the hop after *that* — being a `POST` for a
while doesn't "lock in" staying one; each redirect response is judged on
its own status code, independent of how the request arrived at it.

Verified two ways:
- **Host**: the full existing suite passes unchanged.
- **QEMU (`tools/redirect_preserve_qemu.py`)**, against a real TLS 1.3
  server: a genuine four-hop chain, `POST` →307→ `POST` →308→ `POST`
  →302→ `GET`. The server confirms the *exact same body bytes* arrive
  after both the 307 and the 308 hop (not just "some body," the literal
  original bytes), and that the final 302 hop really does downgrade to a
  bodyless `GET` with no `Content-Length` at all — proving the per-hop,
  non-sticky decision described above actually happens on the wire, not
  just in the design. All 11 checks pass, and the full existing host +
  QEMU regression suite — including 16.1's own 302-downgrade test, still
  exercising the *other* branch of this same decision — is unaffected.

## Step 16.4 — multipart/form-data

16.1's POST could only ever send one shape of body:
`application/x-www-form-urlencoded`, hardcoded inside `build_request()`.
That's fine for a simple form, but file uploads — the other half of what
`multipart/form-data` (RFC 2388, obsoleted by RFC 7578) actually exists
for — need each field as its own MIME part with its own headers, behind a
boundary the body's own bytes can't accidentally collide with. Since this
client already had a working POST pipeline end to end (method, body,
redirects, auth), the real work was building the multipart encoding itself
and giving `build_request()` a `Content-Type` it didn't have to guess.

**`content_type` becomes a first-class parameter**, threaded everywhere
`body`/`bodylen` already were: `build_request()`, `fetch_request()`,
`fetch()`, and `fetch_one()`'s per-hop `req_content_type`. `NULL` still
means "default to url-encoded" (a plain `--post` never has to know this
parameter exists), but a caller can now hand `build_request()` its own
value. 16.3's redirect rule — 307/308 preserve, everything else downgrades
to a bodyless GET — was written generically enough three phases ago that
extending it to a third piece of per-request state was one more variable
in the same reset line, not new logic.

**Encoding a field is bounds-checked against the real body cap, not an
intermediate buffer.** `build_multipart_body()` writes every literal,
field name, and value straight into the final output buffer through
`mp_app()`, which checks remaining capacity on every single append — there
is no smaller fixed-size header buffer of its own that a long field name
could silently overflow independently of the real `POST_BODY_MAX` cap.
Both a plain `--post` and a `--post-multipart` body now share that same
cap: given no `stat`/`lseek` syscall exists to size a file up front (see
below), and no allocator worth trusting with the request's stack-adjacent
buffers, one shared, already-proven-safe size is simpler and safer than
inventing a second, larger one for multipart alone.

**A `field=@localfile` value reads a real file off Aurora's own FAT32
disk.** `open()`/`read()` in a loop until EOF or the body cap is hit — the
same shape `user/cat.c` and `user/viewer.c` already use, since there's no
`stat`/`lseek` syscall to size a file in advance. The file part is sent
with the path's last component as its `filename` and a fixed
`application/octet-stream` Content-Type; this client doesn't sniff a type
from the extension, matching `POST_BODY_MAX`'s own framing of this program
as "a diagnostic CLI, not a general uploader."

**The boundary itself is intentionally not cryptographically random.** It
only needs to be unlikely to collide with a field's own text — nowhere
near the bar TLS's client random needs — so it reuses `fetch_begin()`'s own
`perf_us() ^ getpid()` LCG pattern (see that function's comment: still not
suitable for anything security-sensitive) with a different salt, rather
than inventing a second non-cryptographic RNG for no real benefit.

Verified two ways:
- **Host**: the full existing suite (crc32/inflate/gzip/cookiejar/base64)
  passes unchanged — there's no host-testable unit here on its own (unlike
  base64 or the cookie jar), since multipart encoding is entangled with
  `httpsget.c`'s freestanding request pipeline; QEMU is the acceptance
  surface for this phase.
- **QEMU (`tools/multipart_qemu.py`)**, against a real TLS 1.3 server: a
  fresh `UPLOAD.TXT` file is baked directly onto `disk.img` for the run
  (via `tools/mkfat32.py`, never committed) and `httpsget --post-multipart
  10.0.2.2 /upload name=alice file=@/disk/UPLOAD.TXT` is typed for real.
  The server extracts the boundary from the *actual* Content-Type header
  and parses the *actual* body itself into parts — not trusting httpsget's
  own log line — confirming the text field's exact value, the file field's
  filename and Content-Type, and that the file part's bytes match the real
  on-disk file byte-for-byte. `/upload` then 307-redirects to `/upload2`,
  where the server confirms the Content-Type (boundary included) and the
  raw body are byte-identical to the first request — proving 16.3's
  preservation rule now genuinely covers a multipart Content-Type on the
  wire, not just in the parameter list. All 12 checks pass, and the full
  existing host + QEMU regression suite is unaffected. (Writing this test
  also surfaced a QEMU-harness-only bug, not a code bug: `UPLOAD.TXT` is
  the first typed command in this suite containing uppercase letters, and
  QEMU's HMP `sendkey` takes lowercase physical-key names — typing the
  literal character `U` isn't a recognized key and was silently dropped,
  not rejected, so the fix is `shift-<lowercase>` for any uppercase letter
  in a typed command, the same class of gap `-`/`:`/`=`/`&` closed in
  earlier phases.)

## Step 16.5 — a general `--method`

Every phase through 16.4 hardcoded a binary choice: a request was either
GET or POST, decided once by a `method[0] == 'P'` check in `main()`. That
was already fragile the moment PUT and PATCH entered the picture — both
also start with `'P'` — so the real first step of this phase was replacing
that check with something that actually distinguishes methods, not
extending it.

**A table, not more flags.** `KNOWN_METHODS` pairs each of
GET/HEAD/OPTIONS/DELETE/POST/PUT/PATCH with whether it carries a body;
`--method <VERB>` validates against it and rejects anything else by name
(`method_lookup()`), and `method_body_bearing()` replaces the old
`[0]=='P'` hack everywhere it mattered — deciding which of `--post`'s
body-shaped argument parsing (one path, one body token) or GET's bodyless,
multi-path parsing a given invocation should use. `--post` itself didn't
change: it's exactly `--method POST`'s older spelling now, kept only
because this suite's own earlier scripts already depend on the flag
existing. The genuinely notable part is what *didn't* need to change:
`build_request()`, `fetch_request()`, `fetch()`, and `fetch_one()` all
already took `method` as a plain string with no special-casing beyond
what the CLI layer decided — so PUT, PATCH, DELETE, HEAD, and OPTIONS all
work correctly through the entire TLS/redirect/auth/cookie pipeline
without a single line of change below `main()`'s argument parsing.

**HEAD surfaced a real correctness gap, not just a CLI gap.** RFC 7230
§3.3.3 rule 1: a response to HEAD is *always* terminated by the header
block's blank line, full stop — whatever `Content-Length` says (and a
real server does send one, describing what the equivalent GET would have
returned) does not describe actual bytes on the wire for a HEAD response.
Every earlier phase's response-framing logic (`resp_feed()`'s `g_target`
computation, `reusable()`'s reuse decision) trusted `Content-Length`
unconditionally, because until this phase every request that could
produce a response was allowed to have a real body. A keep-alive HEAD
response advertising a large `Content-Length` would have made the read
loop in `fetch_request()` wait for body bytes a compliant server will
never send — a genuine hang, not a wrong answer, and one that would only
show up against a real server, never in a design review of the diff. The
fix is two small, coordinated pieces of state carried by the existing
response-accumulator globals (`g_no_body`, `g_cur_method`, set from
`resp_reset()`'s new `req_method` parameter): `resp_feed()` sets
`g_target` to just the header length for a HEAD response regardless of
`Content-Length`, and `reusable()` now takes the request method too, so a
HEAD response's real (always-zero) body length — not its claimed one —
governs whether the connection is safe to keep for the next request.

Verified two ways:
- **Host**: the full existing suite passes unchanged.
- **QEMU (`tools/method_qemu.py`)**, against a real TLS 1.3 server: `--method
  PUT` with a real body confirms the exact method and bytes arrive
  (reusing `--post`'s own already-proven body path, just under a
  different verb); `--method DELETE` confirms the request carries no body
  or `Content-Length` at all. The critical scenario is `--method HEAD`
  against a server that responds with `Content-Length: 999999` and
  `Connection: keep-alive` but sends *zero* actual body bytes and never
  closes the connection afterward, exactly like a real server's HEAD
  response and exactly the shape that would hang an un-special-cased
  client forever — the test's own wait budget is deliberately left at
  this suite's ordinary duration (not padded for "in case it's slow") so
  that if the fix were missing, `status=200` would simply never appear in
  the log and the check would fail visibly rather than the test quietly
  waiting long enough to mask a hang. All 12 checks pass, and the full
  existing host + QEMU regression suite — including 16.1's `--post` path,
  now proven to still work as `--method POST`'s validation makes it
  through unchanged — is unaffected.

## Step 17.0 — ALPN

With 16.x closed out, Aurora has a genuinely complete HTTP/1.1 client:
GET/HEAD/OPTIONS/DELETE/POST/PUT/PATCH, redirects, keep-alive, session
resumption, cookies, gzip, authentication, multipart. The next layer up —
whether that ends up being HTTP/2 or eventually a browser stack — needs
ALPN first: without it, a server has no way to know during the TLS
handshake itself that this client can speak anything beyond plain HTTP/1.1,
and most modern servers won't offer HTTP/2 to a connection that never asked
for it. This phase is deliberately *just* that negotiation, RFC 7301, with
no HTTP/2 framing behind it yet — a small, self-contained TLS-layer
addition ahead of a much larger one.

**Opt-in, to protect the RFC 8448 byte-exact vectors.** `tls_build_client_
hello()` gains `alpn_protocols`/`alpn_count` parameters, written as extension
type 16 exactly like `psk_key_exchange_modes`/`pre_shared_key` before it —
same `w_open16`/`w_close16` pattern, same placement rule (it has to come
*before* `pre_shared_key`, which RFC 8446 §4.2.11 requires to stay the very
last extension). When `alpn_protocols` is NULL (the default, set in `tls_
client_init()` and only changed by the new `tls_client_offer_alpn()`, called
by `httpsget`'s `fetch_begin()` only when `--alpn` was given), the extension
is omitted entirely — every ClientHello built without asking for ALPN is
byte-identical to every ClientHello before this phase existed. This mattered
enough to check directly: investigating this phase turned up that this
codebase's RFC 8448 §3/§4 vectors don't actually do an exact byte comparison
against `tls_build_client_hello()`'s live output (the byte-exact ones are
pre-baked hex fed straight into the transcript, bypassing the builder;
the ones that *do* call the builder check structurally, e.g. "does the
output contain the ticket bytes," not "is it identical to this string") —
so an unconditional extension wouldn't actually have broken anything
measurable. The opt-in design was kept anyway: it's the same shape 15.7's
PSK offering already established, it's a one-line difference, and "adding a
feature changes wire bytes only when a caller asks for the feature" is
worth having as an explicit property rather than an accident of what the
test suite happens to check.

**EncryptedExtensions gets parsed for the first time.** Every phase through
16.5 transcripted EncryptedExtensions blindly, never interpreting it — there
was nothing in it any earlier phase needed. `tls_parse_encrypted_extensions()`
adds a bounds-checked walk (mirroring `tls_parse_server_hello()`'s existing
extension loop) that extracts the ALPN selection, if present, and otherwise
skips whatever it doesn't recognize. Its result is treated as **best-effort**:
a parse failure does not abort the handshake, unlike ServerHello or
Certificate. Everything in this message is optional metadata a real server
sends alongside authentication that happens in later messages — refusing an
otherwise-valid connection over a parsing quirk here would be a worse
failure mode than simply not detecting ALPN, and there was a concrete reason
for caution: this parser now runs on *every* connection, resumed or not,
ALPN requested or not, so a bug in it could regress ordinary HTTPS fetches
that have nothing to do with ALPN at all. (The bounds-checking itself is not
relaxed by this leniency — only the decision to reject the connection on a
structural violation is skipped; an out-of-bounds read is still prevented
exactly as rigorously as everywhere else in this file.)

**A selected `h2` is refused, not attempted.** If the server picks `h2`
from the offered list, `fetch_begin()` prints the reason and closes the
connection immediately rather than sending an ordinary HTTP/1.1 request
line to a peer that now expects HTTP/2 framing — that would desync or hang,
not degrade gracefully. `--alpn`'s offered list is `{"h2", "http/1.1"}`
specifically so a real test server has a genuine choice to make (a
one-option list would only prove the extension round-trips, not that
Aurora reacts correctly to a server picking the option it can't use yet).

Verified two ways:
- **Host (`make tls-test`)**: 8 new ClientHello-construction checks (no-ALPN
  unaffected, both offered names present, exactly +18 bytes for the
  extension, and — combined with a PSK offer — ALPN's byte offset
  confirmed to land before the ticket's, locking in the §4.2.11 ordering
  rule) plus 13 new `tls_parse_encrypted_extensions()` checks (`h2` and
  `http/1.1` selections extracted correctly, no-extensions-at-all leaves
  the negotiated flag cleared and the output buffer un-stale, an unrelated
  extension alongside ALPN doesn't confuse the skip-unknown loop, and two
  malformed-input cases are rejected without over-reading). The full
  existing host suite passes unchanged, and — the whole point of the
  opt-in design — `make tls-trace-test`'s RFC 8448 §3/§4 vectors still
  pass byte-exact.
- **QEMU (`tools/alpn_qemu.py`)**, against a real TLS 1.3 server with its
  own independent (OpenSSL-backed) ALPN implementation: a server that can
  only offer `http/1.1` selects it and Aurora proceeds completely
  normally; a server that prefers `h2` gets it, and Aurora's own log shows
  the refusal while the server *independently* confirms zero bytes ever
  arrive on that connection after the handshake completes — proving Aurora
  really stopped, not just misreported success; `--alpn` omitted against a
  server that supports both proves no extension was sent at all. All 13
  checks pass. Because `EncryptedExtensions` parsing is now unconditional
  for every connection, this phase's regression pass was widened beyond
  the usual handful of scripts to a 12-script sweep covering every
  existing QEMU acceptance test in the suite, including 15.7's PSK
  resumption (a resumed handshake still processes EncryptedExtensions,
  just skipping Certificate/CertificateVerify) — all pass unaffected.
  (Writing this test also surfaced a test-harness-only limitation, not a
  code bug: `httpsget`'s CLI has no way to target a non-443 port directly
  — `fetch_one()` hardcodes `u.port = 443` for whatever `<host>` argument
  it's given — so a first draft of this script tried to reach three
  separate per-scenario servers on three different ports and silently hit
  the wrong one twice. Fixed by using a single port-443 server whose
  `SSLContext.set_alpn_protocols()` is reconfigured between the three
  sequential QEMU boots instead.)

## Step 17.1.1 — the HTTP/2 connection-establishment handshake

17.0 stopped the instant ALPN selected `h2`: a clean, deliberate refusal,
correct as far as it went, but it never actually exercised anything HTTP/2-
shaped on the wire. RFC 7540 §3.5/§6.5 make two things mandatory before
*anything* else can happen on an h2 connection — the client's 24-byte
connection preface and a SETTINGS/SETTINGS-ACK exchange in both directions
— and that pair is small and self-contained enough to be a real first slice
of HTTP/2 rather than another "not yet" stub. `17.1.1` implements exactly
that pair and nothing past it: no HEADERS, no DATA, no streams.

**A new top-level `http2/` directory**, alongside `crypto/`/`tls/`/`x509/`/
`compress/` — freestanding, portable, no libc, wired into the Makefile the
same way `compress/` was in 15.10 (added to `TLS_U_SRC`/the `%.tlsu.o`
pattern's include path, plus its own `h2-test` host target). `frame.c` is
the smallest reusable unit, matching how `compress/crc32.c` was one
primitive before `inflate.c` needed it: read/write the 9-byte frame header
(RFC 7540 §4.1) — 24-bit length, 8-bit type, 8-bit flags, 31-bit stream ID
with a reserved top bit that's masked to 0 on write and simply ignored on
read (per §4.1: "unused flags/bits MUST be ignored on receipt", the same
posture as an unrecognized extension in 17.0). `settings.c` builds the two
concrete frames this phase needs — an empty SETTINGS (Aurora's own
announcement: no special preferences) and a SETTINGS ACK (RFC 7540 §6.5:
zero-length payload is a hard requirement, not just Aurora's own choice) —
plus a `h2_settings_payload_valid()` check (a real SETTINGS frame's payload
must be a multiple of 6 bytes, one 6-byte parameter at a time) used only to
confirm a received SETTINGS is *shaped* correctly; 17.1.1 has no use for any
individual parameter's *value* yet, so none are interpreted.

**`h2_handshake()`, in `user/httpsget.c`**, replaces the old refuse-outright
branch. It reuses `fetch_request()`'s own already-proven send/receive shape
(`tls_conn_send_app()` → `write_all()` to send; `tls_reader_next()` /
`tls_conn_recv_app()` / a raw `read()`-and-`tls_reader_feed()` fallback to
receive) verbatim — the only genuinely new piece is what happens to the
*plaintext* once decrypted: instead of feeding HTTP/1.1 text to `resp_feed()`,
it walks raw frame bytes. Two details made this the trickiest part of the
phase, both because a TLS record boundary has no relationship whatsoever to
an HTTP/2 frame boundary:

- **A frame header can arrive split across two separate reads.** The 9
  header bytes might straddle a TLS record boundary (or even a raw socket
  `read()` boundary) exactly like any other byte stream can fragment
  anywhere. A small `hdrbuf`/`hdrlen` accumulator carries a partial header
  across calls, only calling `h2_parse_frame_header()` once all 9 bytes are
  in hand — the same "assemble before you interpret" shape `tls_conn`'s own
  `hs_buf` reassembly already uses for handshake messages spanning records,
  just one level further down the stack.
- **A frame's payload has to be fully consumed before the next header can
  be found**, even for a frame type the handshake doesn't care about (the
  server's own SETTINGS carries real parameter bytes Aurora doesn't
  interpret yet, and any other frame type in between needs its payload
  skipped too, or the next header would be misread starting mid-payload).
  A `skip_remaining` counter, decremented across as many reads as it takes,
  handles this uniformly for every frame type — "acknowledge it and act" for
  the two frames being waited for, "just consume the bytes" for anything
  else, including a `GOAWAY` (which additionally ends the attempt
  immediately: the server is refusing the connection outright, and nothing
  being waited for is ever coming after that). A `H2_HANDSHAKE_FRAME_CAP`
  (64) guards against a pathological peer that never sends either frame at
  all — the same role `MAX_REDIRECTS` plays elsewhere in this file.

**Still refuses to fetch, even on success.** A completed handshake proves
the h2 *connection* is healthy, not that a request can be sent over it —
that needs HEADERS framing, which doesn't exist yet. `fetch_begin()` prints
a different, more specific diagnostic depending on whether `h2_handshake()`
itself succeeded or failed, but either way still closes the connection and
returns failure, exactly as 17.0 did. The boundary hasn't moved; what sits
behind it has grown.

Verified two ways:
- **Host (`make h2-test`)**: 22 new cases — frame-header encode/decode
  round-trips across boundary values (a 24-bit-max length, a 31-bit-max
  stream ID), one byte-for-byte known encoding, confirmation that a
  hostile peer setting the reserved top bit can't corrupt the recovered
  stream ID, capacity/range rejection on both write and parse, and the
  SETTINGS/SETTINGS-ACK builders' exact wire bytes plus
  `h2_is_settings_ack()`/`h2_settings_payload_valid()` correctness
  (including that the ACK flag bit means something different on a
  non-SETTINGS frame type, so type has to be checked too, not just the
  bit). The full existing host suite passes unchanged.
- **QEMU (`tools/h2_handshake_qemu.py`)**, against a real frame-level HTTP/2
  test server — a *from-scratch second* Python implementation of the frame
  encoding, not a copy of `http2/frame.c`, so a bug shared between the two
  wouldn't quietly hide behind agreement: the server confirms the exact
  24-byte preface arrives and the client's SETTINGS is genuinely empty,
  then sends back a deliberately *non-empty* SETTINGS (one real parameter,
  proving the client's skip logic handles an arbitrary-length payload, not
  just a zero-length one) immediately followed by an unprompted
  `WINDOW_UPDATE` — exactly the "frame type nobody asked for, right in the
  middle of the exchange" case real servers produce and this phase's design
  exists to tolerate. Both SETTINGS ACKs are confirmed exchanged in both
  directions, and — proving the scope boundary holds on the wire, not just
  in the design — the server confirms nothing at all arrives afterward.
  All 13 checks pass. `tools/alpn_qemu.py`'s own h2-selected scenario
  needed updating to match: it used to assert "no bytes ever arrive" (true
  under 17.0's outright refusal); now that Aurora genuinely attempts the
  handshake, that assertion became false by design, so it now checks that
  the *real preface* arrives instead — a strictly stronger proof that the
  new code path is really firing, not a weaker one. Because `h2_handshake()`
  is new code inside `fetch_begin()` (even though only reachable via
  `--alpn` selecting `h2`), this phase's regression pass repeats 17.0's
  full 12-script QEMU sweep — all pass unaffected.

## Step 17.1.2 — DATA frame + a generic HTTP/2 frame reader

17.1.1's `h2_handshake()` worked, but its frame reading was hand-rolled and
narrow: a `hdrbuf`/`hdrlen` accumulator for the header, a `skip_remaining`
counter that threw away every payload byte regardless of frame type — fine
for a handshake that only ever needed to *notice* SETTINGS/SETTINGS-ACK/
GOAWAY and ignore everything else, but nothing about it could hand a later
piece of code the *contents* of a frame it cared about. Streams (17.3) and
HEADERS (17.1.3) both need exactly that, so 17.1.2 builds it once, properly,
instead of letting every future h2 feature re-invent its own version.

**`h2_frame_reader` (`http2/frame.c`)** plays the same role for HTTP/2
frames that `tls_record_reader` already plays for TLS records one layer
down: feed it arbitrarily-chunked bytes, get back complete frames. Two
design choices worth naming:

- **`feed()` returns how many bytes it consumed, not void.** An HTTP/2
  frame boundary has no relationship to a TLS record boundary, so one
  `tls_conn_recv_app()` call's plaintext can contain anywhere from a
  fragment of one frame to several complete ones back to back. Rather than
  buffer an unbounded number of pending frames (a real queue, unbounded
  memory), `h2_frame_reader` holds exactly one frame — header plus payload
  — at a time, and `feed()` simply stops accepting bytes the instant that
  one frame is complete, telling the caller how much it actually took. The
  caller's job (now `h2_handshake()`'s own inner loop) is a small,
  mechanical pattern: feed, drain everything ready via `next()` in a loop,
  and if there's leftover input, feed the remainder again.
- **The buffer is sized to RFC 7540 §6.5.2's default `SETTINGS_MAX_FRAME_
  SIZE` (16384) plus the 9-byte header — `H2_FRAME_PAYLOAD_MAX`.** Aurora
  never negotiates a larger one (its own SETTINGS, 17.1.1, is empty, i.e.
  every default applies), so a frame declaring more than that is
  unambiguously a misbehaving peer, not a limit Aurora imposed on itself —
  `feed()` rejects it outright (a frame size error, RFC 7540 §4.2) rather
  than trying to accommodate it.

**DATA frame support (`http2/data.c`)** is the other half: `h2_data_parse()`
decodes RFC 7540 §6.1's optional-padding shape (`Pad Length` byte, then
data, then that many bytes of padding), rejecting the case the RFC calls
out explicitly — padding whose declared length is greater than or equal to
the whole payload — as a connection error rather than reading past the
buffer; `h2_data_build()` is the send-side mirror (Aurora never needs to
*send* padding, only tolerate receiving it, so the builder doesn't offer
the option). `h2_handshake()` itself doesn't act on a DATA frame's
contents yet — nothing has opened a stream for one to belong to — but it
now names it correctly in its own log rather than silently treating it as
one more unknown type to skip, which is the concrete, externally-visible
proof that "recognizes every frame type" is true today, not aspirational.

Verified two ways:
- **Host (`make h2-test`)**: 23 new cases for the reader (a whole frame in
  one `feed()` call, the identical frame fed one byte at a time, a frame
  whose *payload* — not just its header — is split across two `feed()`
  calls at an arbitrary boundary, two complete frames delivered in a
  single `feed()` call draining correctly via two separate `next()`
  calls, and an oversized frame declaration rejected before any payload
  is buffered) and for DATA (unpadded, padded, both rejection cases from
  §6.1, and an END_STREAM flag round-trip through `h2_data_build()`). The
  full existing host suite passes unchanged.
- **QEMU (`tools/h2_handshake_qemu.py`, extended)**: the same real
  frame-level HTTP/2 test server from 17.1.1 now also sends a genuine
  *padded*, `END_STREAM`-flagged DATA frame — built by a second,
  independent Python encoder, not `http2/data.c` itself — on a stream
  nothing ever opened, interleaved between its SETTINGS and its SETTINGS
  ACK. Aurora's log names it correctly ("DATA frame seen") without the
  handshake's completion being disrupted, confirmed alongside every check
  from 17.1.1 (preface, SETTINGS exchange in both directions, nothing
  sent afterward). All 14 checks pass (13 before, plus the new one).
  Because `h2_handshake()` was *refactored*, not just extended — its
  entire frame-reading loop now goes through new code — this phase
  doesn't stop at re-running the DATA-frame-aware test: it repeats the
  full prior regression sweep (13 QEMU scripts, the 12 from 17.0 plus
  `alpn_qemu.py`) end to end, to confirm the refactor changed nothing
  about externally-observable behavior. All pass unaffected.

## Step 14.x.6/14.x.7 — secure HTTPS proven END-TO-END inside QEMU

14.x.6 chased a phantom: a handshake that reached 200 on the host appeared to
fail "at the record layer" in QEMU. Deep instrumentation of the live QEMU path
showed there is **no engine bug** — the i686 crypto, key schedule, AEAD, record
layer and kernel TCP/IP stack are all correct. With certificate validation off,
httpsget in QEMU completes a full TLS 1.3 handshake against a live server and
returns HTTP 200, reliably. The apparent "record error" was the X.509 layer
**correctly rejecting an untrusted certificate** (`TLS_DRIVE_PROTOCOL`, FSM error
`TLS_ERR_CERT`); the host probes had simply skipped trust or used a matching
anchor. The specific reason is now preserved (`tls_client.cert_reason`) and
printed by httpsget, instead of being mis-blamed on the (closed) P-384 gap.

14.x.7 then proved the **secure** path with validation ON. `tools/securehttps_qemu.py`
generates a fresh controlled PKI for each key type — Root CA → Intermediate →
Leaf (leaf SAN `10.0.2.2`) — installs the test Root into Aurora's trust store,
serves the leaf+intermediate from a local TLS 1.3 server (ChaCha20-Poly1305 +
X25519) over SLIRP, and runs `httpsget 10.0.2.2 /` in QEMU. For **RSA, ECDSA
P-256 and ECDSA P-384** the run reaches *Certificate chain OK → CertificateVerify
OK → Peer authenticated → CONNECTED → HTTP 200* — depth-N path building,
basicConstraints/keyUsage, hostname validation and the per-curve signature all
exercised end-to-end, inside the OS. No private keys are committed (the PKI is
regenerated per run; the production trust store is restored on exit).

The from-scratch HTTPS stack is now a closed cycle, demonstrated in QEMU:

```
TCP ✓   TLS 1.3 ✓   X25519 ✓   ChaCha20-Poly1305 ✓
RSA ✓   ECDSA P-256 ✓   ECDSA P-384 ✓
X.509 depth-N ✓   basicConstraints/keyUsage ✓   hostname validation ✓
HTTPS (validation ON) ✓   QEMU ✓
```

A real public-site 200 from QEMU now depends only on trust-store coverage
(whether the site's chain builds to one of the bundled roots), not on any
TLS/crypto/PKI capability — that is the 14.0.5 direction. With the correctness
cycle closed, 15.0 (memory reduction) optimises a fully working system.
Aurora has no wall clock, so the validity instant is a build-time constant
(overridable as `argv[3]`); keep it inside the target cert's window.

Remaining after the QEMU acceptance: 15.0 trims the per-cert memory; 14.x adds
P-384/SHA-384 to open the ECDSA slice of the public web.
