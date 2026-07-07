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
| **17.1.3** | **A real HEADERS frame, HPACK static table only** — new `http2/hpack.c` (RFC 7541 prefixed-integer and string-literal encoding, "Indexed Header Field" and "Literal Header Field *without* Indexing" representations — deliberately not "with incremental indexing", since Aurora tracks no dynamic table of its own to stay in sync with one it would be telling the peer to build) and `http2/headers.c` (`h2_build_headers()`, assembling `:method`/`:scheme`/`:authority`/`:path`/`user-agent` into one HPACK-compressed HEADERS frame using ONLY RFC 7541 Appendix A's static table — no Huffman, no dynamic table, both later phases). `h2_send_request()` sends it once the connection-establishment handshake (17.1.1/17.1.2) succeeds, opening stream 1 (RFC 7540 §5.1.1) with a genuine GET to `u->host`/`u->path`, then recognizes (by frame type only, still not HPACK-decoding) whatever response frame comes back before `fetch_begin()` still ends the attempt — response decoding needs Huffman and/or the dynamic table, which a real server's response headers routinely require | `make h2-test` (22 new cases: RFC 7541 §5.1's own worked example — 1337 with a 5-bit prefix — matches byte-for-byte, indexed/literal/multi-byte-continuation representations checked individually, then four complete HEADERS frames — `GET /`, `GET` with a non-root path plus a user-agent exercising the multi-byte index for entry 58, `POST`, and `PUT` — each checked against hex byte sequences hand-derived directly from RFC 7541's own encoding rules, not copied from any tool); `tools/h2_handshake_qemu.py` extended with a genuine, independent, from-scratch Python HPACK *decoder* (not Aurora's `http2/hpack.c`, and not any third-party package — installing one via `pip` was correctly blocked by this session's own permission policy as an undeclared external dependency) that receives Aurora's real HEADERS frame and decodes `:method=GET`, `:scheme=https`, `:authority=10.0.2.2`, `:path=/whatever` and Aurora's own user-agent string, then answers with a real (single-byte, statically-indexed) `:status: 200` HEADERS frame of its own, which Aurora correctly recognizes by type without decoding it — All 23 checks pass. Writing the C-side hex vectors caught a real off-by-one in the *test itself* (a hand-counted user-agent length one byte too long, so the encoder faithfully copied the string's own NUL terminator in as if it were data — the byte-mismatch check caught it immediately; `http2/hpack.c` was already correct) before it was ever committed. Full existing host suite and the 13-script QEMU regression sweep from 17.1.2 all pass unaffected | ✅ |
| **17.2.1** | **HPACK Huffman decoding** (RFC 7541 §5.2/Appendix B, new `http2/huffman.c`) — decode-only, matching 17.1.3's own decision to leave Aurora's *encoder* (`hpack.c`) alone: this client never sends a Huffman-coded string, but a real server's response routinely does, so reading one back needs a decoder regardless. `hpack_huffman_decode()` is a bit-by-bit canonical-Huffman walk: accumulate one bit at a time into a candidate `(code, len)` and scan the 256 real symbols (never EOS/256 itself — RFC 7541 §5.2 forbids a sender from ever encoding it) for an exact match; a run longer than the longest real code (28 bits) or than EOS's own 30-bit all-ones code can only mean corrupt input, and trailing padding bits must themselves be a prefix of that same all-ones pattern. The 257-entry code table (256 symbols + EOS) behind it was **not hand-transcribed** — this project has hit exactly that class of error before (the gzip/CRC32/inflate KATs in 15.10, and 17.1.3's own hand-counted user-agent length bug) — instead it was fetched as raw RFC text via `curl` (rejecting `WebFetch`, whose own documentation says large content "may be summarized" by an intermediate model — an unacceptable risk for a bit-exact 257-entry table) and mechanically parsed out of the RFC's own published text with a narrow regex script, which also verified the parse's completeness (257/257 entries, no duplicates or gaps) and cross-checked three RFC-documented values (symbol 47 `/` → `0x18`/6 bits, symbol 0 → `0x1ff8`/13 bits, EOS → `0x3fffffff`/30 bits) before the table was ever written into C | `make h2-test` (11 new cases: RFC 7541 Appendix C.4.1 and C.4.2's own worked Huffman examples — `f1e3c2e5f23a6ba0ab90f4ff` → `"www.example.com"`, `a8eb10649cbf` → `"no-cache"` — decode byte-for-byte correct; empty input decodes to an empty string; a single `0x00` byte decodes one real symbol then is correctly rejected for invalid (non-all-1s) padding; four bytes of `0xff` (a run longer than any valid code) is rejected rather than silently treated as EOS; an undersized output buffer is rejected, not truncated). Before any C was written, the exact same algorithm was prototyped in Python against both RFC C.4 vectors, to catch a design bug independent of any transcription bug in the table. Standalone capability only — not yet wired into `httpsget.c`'s live h2 response path, since decoding a real response also needs the dynamic table (17.2.2); full existing host suite passes unaffected, and the full 16-script QEMU regression sweep (every `tools/*_qemu.py` script, including `h2_handshake_qemu.py` itself) re-run unaffected, since this phase only adds a new, still-unused object file to the link | ✅ |
| **17.2.2** | **HPACK dynamic table + full header block decode** (RFC 7541 §2.3.2/§4/§6, new `http2/hpack_table.c` and `http2/hpack_decode.c`) — completes decode-side HPACK. `hpack_table.c` holds the full 61-entry static table (RFC 7541 Appendix A, mechanically extracted the same way as 17.2.1's Huffman table — this time each string's length is `sizeof(x)-1`, compiler-computed rather than hand-counted, closing off the exact class of mistake a hand-counted user-agent length caused in 17.1.3) plus a decode-side dynamic table: a fixed 4096-byte arena (matching the RFC 7540 §6.5.2 default `SETTINGS_HEADER_TABLE_SIZE` that applies as long as Aurora's own SETTINGS stays empty — no legally-behaving peer can ever need more than this decoder can hold) storing entries FIFO, insertion evicting the oldest as needed to fit under the current max size, a Dynamic Table Size Update (§6.3) shrinking that max and evicting accordingly, and index resolution across RFC 7541 §2.3.3's unified space (1-61 static, 62+ dynamic, most-recent-first). `hpack_decode.c` adds §5.1's integer decode and §5.2's string-literal decode (raw or Huffman, via `huffman.c`), dispatching every §6 representation — Indexed Header Field, Literal with Incremental Indexing (the one that grows the table), Literal without Indexing, Literal Never Indexed, and Dynamic Table Size Update — into a caller-supplied list of decoded header fields. Aurora's own encoder (`hpack.c`, 17.1.3) is untouched, by design: RFC 7541 §2.3.2 makes the two directions' dynamic tables independent, so tracking what a *peer's* encoder does carries none of the send-side synchronization risk 17.1.3 deliberately avoided | Writing the tests surfaced a real bug before any of this shipped: the decoder initially returned raw pointers into the dynamic table's own byte arena for indexed lookups, but a *later* representation in the same header block can evict and compact that arena out from under an *earlier* one's already-decoded field — not a hypothetical, but literally what RFC 7541's own Appendix C.5.3 example does (a `cache-control` entry read early in a response is evicted later in that same response). Fixed by copying every table-resolved name/value into the caller's scratch buffer immediately upon resolution, before anything else in the block can run. `make h2-test` (86 new cases): the RFC's own isolated representation examples (Appendix C.2.1-C.2.4); the full three-request sequence from Appendix C.3 with the dynamic table growing across calls to the *same* table instance, verifying decoded fields, table entry count, and table byte-size after each request against the RFC's own documented intermediate state (including a dynamic entry referenced back by index 62, then by index 63 once a second insertion pushes it one further back — "Indexed Dynamic Entries" from the roadmap, proven against the RFC's own sequence rather than a self-invented one); the full three-response sequence from Appendix C.5 with `SETTINGS_HEADER_TABLE_SIZE` set to 256 (as the RFC itself specifies) to force real evictions, including the exact C.5.3 case that caught the arena-aliasing bug above; `Dynamic Table Size Update` exercised both as a direct API call (shrinking evicts down to what fits, down to and including emptying the table) and inline within a real header block; and malformed-input rejection (an indexed field pointing past the last live entry, index 0, a size update past the 4096-byte arena cap, a string literal whose declared length runs past the input, an `out_cap` too small for even one field, a `scratch` buffer too small for one decoded string). Full existing host suite passes unaffected. Not yet wired into `httpsget.c` — assembling a decoded header block into an `http_response`-shaped result, and reading the accompanying DATA frame(s), is Phase 17.3; the full 16-script QEMU regression sweep re-run unaffected, since this phase again only adds new, still-unused object files to the link | ✅ |
| **17.3** | **The first genuinely complete HTTP/2 response** — pure integration, no new protocol capability: `h2_fetch()` (`user/httpsget.c`, replacing 17.1.3's `h2_send_request()`) reads stream 1 to completion, HPACK-decoding the response HEADERS (against `session_slot`'s own persistent per-connection `hpack_dyn_table`) and translating the decoded field list into an HTTP/1.1-shaped status-line-plus-headers text block (`h2_synthesize_header_block()`), fed together with every DATA frame's payload through the EXISTING `resp_feed()` — the same function an HTTP/1.1 response's bytes already flow through. `fetch_one()` needed zero changes: a `fetch_result_t` is a `fetch_result_t` regardless of which wire protocol produced it, exactly the "the upper layer never needs to know" goal this phase was scoped around. A synthesized `Connection: close` line makes the *existing* keep-alive computation come out false for every h2 response, so the *existing* `reusable()`/`slot_close()` logic in `fetch()`/`fetch_one()` already closes an h2 connection after its one response, with no h2-specific code of its own — Phase 17.3 deliberately keeps to one client stream, no multiplexing, and no PRIORITY/PUSH_PROMISE/CONTINUATION/flow-control handling beyond what finishing that one stream needs; carrying a method/body other than GET over h2 is equally out of scope. `h2_text_safe()` rejects any decoded name/value containing CR/LF (or, for a name, `:`) before it's spliced into the synthesized text — the HTTP response-splitting equivalent for this translation step, since Aurora's own HPACK decoder validates wire *syntax*, not HTTP header *semantics* | Writing the QEMU test caught a real integration bug pre-commit: the first draft had `h2_fetch()` return directly with `FETCH_OK`, which skipped `fetch_request()`'s own Set-Cookie-scanning tail (shared code, positioned *after* the HTTP/1.1-vs-h2 branch) entirely — an h2 response's cookies were silently never stored. Fixed by having `h2_fetch()` return only a `closed` flag and letting the *existing* shared tail (staleness check, Set-Cookie scan via `http_find_header()`, `*out` fill) run unchanged for both paths — the same reuse discipline the rest of this phase applies everywhere else, this time caught by a real acceptance test rather than by inspection. `tools/h2_handshake_qemu.py` (extended a fourth time, now covering 17.1.1 through 17.3 in one script) sends a real response: a HEADERS frame using "Literal with Incremental Indexing" for `:status`/`content-type`/`set-cookie` (indexed names, literal values — exercising real dynamic-table growth, not just the 17.2.2 host tests' own vectors) plus one fully literal header, then three DATA frames covering every item on the roadmap's own DATA checklist in one response — a sequence of frames, a zero-length one, padding, and `END_STREAM` on the last. All 25 checks pass: the real page content and the real `:status: 200` reach Aurora's own printed output (`status=200`, the actual HTML body text, `200 OK over Aurora TCP->TLS1.3->HTTP`), the decoded Set-Cookie is stored, and the connection closes cleanly afterward with nothing further sent — the first HTTP/2 response Aurora has ever fully understood. Full existing host suite and the complete 16-script QEMU regression sweep (this phase changes shared code in `fetch_request()`, not just adds new files, so every existing script was re-run, not assumed unaffected) all pass with byte-identical HTTP/1.1 behavior | ✅ |
| **17.4.1** | **HTTP/2 request bodies — full 16.5 `--method` parity over h2** — `h2_build_headers()` (`http2/headers.c`) gains `content_type`/`body_len` parameters: when `body_len > 0`, it adds Content-Type and Content-Length (both "Literal Header Field without Indexing" against an indexed NAME, matching this encoder's own static-table-only convention since 17.1.3) and clears END_STREAM on the HEADERS frame — a DATA frame (`h2_data_build()`, already existing from 17.1.2) now follows, carrying the body with END_STREAM on it instead. Content-Length is always derived from `body_len` itself (never a separately-trusted value that could drift from what's actually sent), the same discipline `build_request()`'s own HTTP/1.1 Content-Length already follows. `h2_fetch()` (`user/httpsget.c`) now honors the real `method`/`body`/`bodylen`/`content_type` `fetch_request()` already threads through for HTTP/1.1, instead of hardcoding GET — bringing every one of 16.5's `--method` verbs (GET/HEAD/OPTIONS/DELETE/POST/PUT/PATCH) to h2, not just the three body-bearing ones. Still one DATA frame per request (`POST_BODY_MAX`, 4096 bytes, comfortably fits under `H2_FRAME_PAYLOAD_MAX`) and still one stream per connection — reusing an h2 connection across requests, and an Authorization header over h2, remain explicit follow-ups, not attempted here | `make h2-test` (11 new cases): a POST with a 13-byte body, checked against hex bytes computed by a small from-scratch Python HPACK encoder mirroring `hpack_put_int()`'s own algorithm (this project's established discipline of never hand-deriving a hex vector when a short, independently-checkable script can compute one instead), confirming END_STREAM is clear on HEADERS and the Content-Type/Content-Length bytes are exactly right; the paired DATA frame built separately and checked byte-for-byte; a bodyless GET re-checked byte-for-byte against 17.1.3's own original vector, proving zero behavioral drift for the unchanged case. `tools/h2_post_qemu.py` (new — mirroring how 16.1's own POST support got its own dedicated `post_qemu.py` rather than an ever-growing shared script): `httpsget --alpn --method POST` against a real frame-level server confirms END_STREAM is clear on the request's HEADERS frame, HPACK-decodes it (this script's own independent decoder) to confirm a real Content-Type and the exact real Content-Length arrived, confirms END_STREAM is set on the DATA frame that follows and that its payload is the exact real body bytes, and confirms Aurora's read path still completes correctly (`status=200` reached) right after having just sent a body-bearing request on the same stream — proving the two directions don't interfere. All 18 checks pass. Full existing host suite and the full 17-script QEMU regression sweep (16 prior scripts plus this new one) all pass unaffected | ✅ |
| **17.4.2** | **HTTP/2 connection reuse — sequential streams, no multiplexing** — an h2 connection is no longer closed after its one response. `session_slot` gains `next_h2_stream` (reset to 1 by `fetch_begin()` on every fresh h2 connection, `+= 2` after each `h2_fetch()` call — RFC 7540 §5.1.1: client-initiated stream IDs are odd and strictly increasing), so a second request on the same origin opens stream 3, not another stream 1; `h2_dyn_table` (already per-connection since 17.3) now genuinely spans more than one request too. The forced synthesized `Connection: close` line is gone — `g_hr.keep_alive` is now set directly from `h2_fetch()`'s own return value (did this stream's END_STREAM actually arrive), since HTTP/1.1's own keep-alive computation doesn't map onto h2 (h2 framing needs no Content-Length the way that computation assumes one always exists). `reusable()` gained a `content_length < 0` fast path returning reusable-with-no-size-check: the `FETCH_REUSE_MAX_BODY` cap exists to weigh "is draining the rest of a big HTTP/1.1 body worth it just to reuse the connection" — a question that doesn't apply to h2, where `h2_fetch()` always reads a response to its real end (END_STREAM) as part of getting it AT ALL, so the "cost" the cap is weighing was already paid regardless (this path is provably unreachable for HTTP/1.1, since `http_parse()` itself never sets `keep_alive` true when `content_length` is -1, so zero behavior change there). A latent data-loss bug in `h2_fetch()`'s read loop was also fixed: it used to stop draining a decrypted TLS record the instant the current stream's `END_STREAM` arrived mid-buffer, silently discarding any trailing bytes (harmless before this phase, since the connection was always closed moments later anyway; a real bug once it lives on to carry a second request) — fixed by draining every decrypted chunk fully regardless, only skipping *acting* on frames once the stream is already known complete. The EXISTING `reusable()`/`slot_close()` logic in `fetch()`/`fetch_one()` needed no changes at all — it's just being told the truth about h2 now instead of a hardcoded "never." Still one active stream at a time, in sequence, never multiplexed | `tools/h2_reuse_qemu.py` (new): `httpsget --alpn 10.0.2.2 /a /b` against a real frame-level server that accepts exactly ONE TCP connection for both requests, confirms the second request opens stream 3 (not another stream 1) on that same connection, and — the strongest possible proof of dynamic-table continuity — answers the *second* response using pure "Indexed Header Field" references (RFC 7541 §6.1, zero literal bytes) into dynamic-table entries the *first* response added via incremental indexing, decodable only if `h2_dyn_table` genuinely survived between the two requests. All 20 checks pass: exactly one connection, correct stream IDs, both distinct response bodies received intact, Aurora's own log showing "reusing open connection" (not a second handshake), and both requests reaching `status=200`. Full existing host suite and the complete 18-script QEMU regression sweep (this phase changes `reusable()`, shared with the HTTP/1.1 keep-alive path, so `keepalive_qemu.py` was re-verified with particular care) all pass unaffected | ✅ |
| **17.4.3** | **Minimal HTTP/2 flow control — one active stream's worth** (RFC 7540 §6.9, new `http2/window_update.c`) — the last piece needed for a response over ~32 KB to complete without stalling. `h2_fetch()` now tracks two receive windows, both starting at the RFC 7540 §6.5.2 default `SETTINGS_INITIAL_WINDOW_SIZE` (65535, in effect since Aurora's own SETTINGS stays empty): `session_slot.h2_conn_recv_window` (connection-level, spanning every request on this connection, mirroring `next_h2_stream`/`h2_dyn_table`) and a stream-level one (a local variable, fresh per request). Every DATA frame's FULL payload length — padding included, per RFC 7540 §6.9.1 — decrements both; either going negative means the server sent more than Aurora ever authorized, treated as the protocol violation it is (request aborted). Once either drops to or below half its initial value, `h2_maybe_send_window_update()` sends a real WINDOW_UPDATE topping it back to 65535 — without this, the server would eventually and correctly stop sending, believing Aurora's advertised window was exhausted, with no way for Aurora to say otherwise. Incoming WINDOW_UPDATE frames from the server (connection- or stream-scoped) are recognized and validated (`h2_window_update_parse()`, rejecting a malformed 4-byte payload or the RFC-forbidden zero increment) but deliberately not acted on: Aurora's own request bodies (`POST_BODY_MAX`, 4096 bytes) always fit under the default window regardless of anything the server advertises, so gating sends on it would add real complexity for a wait that can never actually happen. No `SETTINGS_INITIAL_WINDOW_SIZE` parsing needed either — that setting only affects the *sender's* side of a given direction, and Aurora's own receive-side accounting is governed entirely by its own (unmodified, default) advertised value, never the peer's | `make h2-test` (15 new cases): `h2_window_update_build()`/`h2_window_update_parse()` round-tripping a connection-level and a stream-level frame, the reserved top bit (RFC 7540 §6.9: "MUST be ignored on receipt") not corrupting the 31-bit increment, and rejection of a zero increment, an out-of-31-bit-range increment, an undersized output buffer, and a payload that isn't exactly 4 bytes. `tools/h2_flowctl_qemu.py` (new): `httpsget --alpn 10.0.2.2 /big` against a real frame-level server answering with a 200000-byte body — deliberately far past the default window, forced into 13 separate DATA frames by the 16384-byte `H2_FRAME_PAYLOAD_MAX` cap — confirms the server receives BOTH a connection-level (stream 0) and a stream-level (stream 1) WINDOW_UPDATE from Aurora, more than one of each kind sent over the transfer, every received increment RFC-plausible, and — the real proof nothing was silently dropped at the flow-control layer — Aurora's own log reporting exactly `200000 body bytes` received. All 14 checks pass on the first run. Full existing host suite and the complete 19-script QEMU regression sweep all pass unaffected | ✅ |
| **17.5.1** | **HTTP/2 hardening: fuzzing + sanitizer-enabled host testing — opens the "17.5 Hardening" series** — no new RFC surface; the goal is finding real bugs in what's already built, not adding more of it. New `tools/h2_fuzz.c`: a deterministic (fixed-seed, reproducible) fuzz harness feeding random and deliberately malformed bytes into every `http2/` decode entry point a network peer's bytes can reach — the HPACK header-block decoder (including forced-Huffman-bit string literals), the generic frame reader, DATA frame parsing, SETTINGS payload-length validation, WINDOW_UPDATE parsing, and Huffman decode directly — checking not just "did it crash" but that every documented output invariant still holds (a decoded count never exceeds the capacity it was given; a returned pointer always falls inside the buffer it's supposed to point into). New `make h2-fuzz` (fast plain build, many iterations) and `make h2-fuzz-san`/`make h2-test-san` (GCC `-fsanitize=address,undefined` — specifically GCC, not clang, since clang's own sanitizer runtime isn't installed in this environment — applied to the fuzz harness and, as a standing regression target, the *existing* fixed-vector `h2-test` suite too) | **Two real bugs found and fixed, both before this phase's own commit landed anywhere:** (1) A genuine out-of-bounds read in `hpack_table_get()` (`http2/hpack_table.c`) — `if ((int)dyn_index >= t->count)` cast an `unsigned` value to `int` for the comparison; an HPACK index whose `dyn_index` (index − 62) exceeded `INT_MAX` (any value up to `UINT32_MAX` is a legitimately-encoded RFC 7541 §5.1 integer as far as the decoder's own overflow check is concerned) wrapped to a *negative* `int`, silently passing the bounds check and indexing `t->entries[]` with a massive out-of-range value — a real, network-triggerable memory-safety bug a malicious or simply buggy HTTP/2 server could hit with an ordinary-looking HEADERS frame. Fixed by comparing entirely in unsigned arithmetic (`dyn_index >= (unsigned)t->count`), which is both correct for every possible `index` value and exactly as cheap. (2) A stack buffer overflow in the TEST HARNESS itself — `tools/h2_test.c`'s `check_hex()` used a fixed `hex[64]` with no capacity check at all; the 98-byte hex vector from 17.2.2's own Appendix C.5.3 test needs 197 bytes, silently overflowing the stack on every `h2-test` run since that commit, undetected because nothing observable happened to depend on the corrupted bytes until ASan's stack redzones caught it here. Fixed by widening the buffer and giving `tohex()` an explicit capacity parameter it now actually checks — fail loudly, the same discipline the production code has followed all along, that this one helper had quietly skipped. Verified: `make h2-fuzz` (6 targets × 200,000 iterations, re-run across 6 independent seeds — 1, 42, 1337, 0xdeadbeef, 0xc0ffee, 999999999 — for over 18 million total operations) all pass after the fix; `make h2-fuzz-san`/`make h2-test-san` (GCC ASan+UBSan, multiple seeds) pass clean; the complete existing host suite and 19-script QEMU regression sweep re-verified unaffected by the `hpack_table_get()` fix (a strict rejection of previously-mishandled out-of-range indices no legitimate response would ever use) | ✅ |
| **17.5.2** | **HTTP/2 hardening: stress & interoperability — closes the "17.5 Hardening" series** — five independent stress dimensions, each with its own QEMU test against a real frame-level (or, for interop, genuinely independent) server: (1) large responses — `user/httpsget.c` gains `--repeat N` (loops `fetch_one()` N times over the same path on one connection — Aurora's own shell caps a typed command at `ARG_MAX`, 16 tokens, so "one path argument per request" cannot reach "hundreds"), used for 1/5/20 MB single-stream responses (`tools/h2_large_qemu.py`); (2) `tools/h2_longlived_qemu.py` — 300 sequential requests over one reused connection, stream IDs reaching 599, the HPACK dynamic table surviving hundreds of insert/evict cycles; (3) `tools/h2_hpack_stress_qemu.py` — a ~3000-byte single header value, 40 `Set-Cookie` headers in one response, three back-to-back Dynamic Table Size Updates in one header block, and 40 fields whose cumulative size forces eviction *within* a single block rather than gradually across many; (4) `tools/h2_goaway_qemu.py` — GOAWAY arriving instead of the server's own SETTINGS, and GOAWAY arriving mid-response after HEADERS plus an incomplete DATA frame; (5) `tools/h2_nginx_interop_qemu.py` — a real, unmodified `nginx` (Ubuntu's stock package, `--with-http_v2_module`, launched from its own throwaway config, never touching the system's default site) as the first peer in this whole project that isn't a hand-rolled Python script | **Three real bugs found, none of them hypothetical — each one only surfaced because this phase pushed past what any prior phase's hand-chosen scenario happened to exercise:** (1) **A genuine TCP protocol bug** (`net/tcp.c`'s `tcp_input()`): a duplicate, out-of-order, or window-rejected segment got ZERO acknowledgment — the ACK-send condition was only `if (c->tcb.rcv_nxt != before)`, true exclusively when a segment actually advanced the receive sequence. RFC 793/5681 require an immediate current ACK in all three cases regardless; without one, a real kernel TCP sender (Linux, not a hand-rolled test peer) has no signal that Aurora already has a segment it retransmitted, and can stall the connection indefinitely waiting for feedback that never comes. First surfaced as a dead stall at ~340 KB into a large response — a size no test before this phase had ever attempted (17.4.3's own flow-control test topped out at 200 KB). Fixed by sending a current ACK for any data- or FIN-bearing segment, not only ones that advance `rcv_nxt`. A related but independent defect in the same area was fixed alongside it: `tcp_tick()` kept blindly retransmitting a still-`pending` segment on a connection that had already gone `TCP_CLOSED` (a RST doesn't itself clear `rtx.pending`) — harmless before, but pointless and it kept spamming a peer that had long since forgotten the connection existed. (2) **Cookies never actually flowed both directions over HTTP/2.** `http2/headers.c`'s `h2_build_headers()` had no cookie parameter at all — a session cookie learned from an h2 response's own `Set-Cookie` (stored correctly the whole time, via the exact same `resp_feed()`/`cookie_jar_set()` path HTTP/1.1 uses) was simply never sent back on a *later* h2 request, even one reusing the very connection that set it; cookie persistence silently only worked in one direction. Found while designing this phase's own "many cookies" HPACK-stress scenario, not by inspection. Fixed: `http2/hpack.h` gains `HPACK_IDX_COOKIE` (static table index 32); `h2_build_headers()` takes an optional cookie value, encoded exactly like `user-agent` (a literal, never dynamically indexed — this encoder never indexes a value that varies per request rather than describing the connection itself); `h2_fetch()` builds it from the cookie jar via `cookie_jar_build_header()`, identically to `build_request()`'s own HTTP/1.1 Cookie header. Verified end to end by `h2_hpack_stress_qemu.py`'s own `/echo` step: 40 cookies set by one response, `COOKIE_JAR_N` (32) forcing real LRU eviction, and the *real* Cookie header on a later real request (decoded by the test's own from-scratch parser) shown to contain exactly the 32 survivors and none of the 8 evicted. (3) **A test-harness bug that looked like a protocol bug until measured.** After fixing (1), a *different* failure appeared further into large-response testing: an outbound WINDOW_UPDATE write failing outright. Root cause was in the test's OWN Python server, not Aurora: `tls.sendall()` returning only means the OS queued the bytes in its own send buffer, not that the peer received them — at this environment's measured real throughput (~1.2-1.5 KB/s; Aurora's own from-scratch ChaCha20-Poly1305 record decryption on an emulated i686 CPU is the bottleneck, not the network), Aurora is still slowly receiving and acking a large response for a long time after `sendall()` returns. The test's server was closing the socket immediately afterward, stranding that still-in-flight data against an already-torn-down socket — any further packet from Aurora (a routine WINDOW_UPDATE ack) got an immediate "no such connection" RST from the peer OS, which then made Aurora's own next write fail outright. Diagnosed by direct measurement (a throughput probe, and a background investigation agent that traced the exact TCP sequence numbers involved) after an initial wrong hypothesis (a data race in `tcp_xmit()`'s shared static buffer) was tried, re-tested, and found NOT to fix the symptom — the wrong fix was reverted rather than kept on the theory that it might help. Fixed in the test's own server: keep draining (as real H2 frames, not raw discarded bytes — a second bug in the fix's own first draft) whatever Aurora sends back until it goes idle, before closing. Given the ~1.2-1.5 KB/s throughput ceiling this phase measured, 5 MB and 20 MB were tested with a single fetch each rather than `--repeat 2`'s double-fetch (which 1 MB alone still uses) — the "no leak on repeat" property that would have proven is already established twice over: once at 1 MB here, and independently at full connection-reuse scale by item 2's own 300-request run. Verified: all five QEMU tests pass — 1/5/20 MB (`h2_large_qemu.py`), 300 requests (`h2_longlived_qemu.py`), all HPACK-stress scenarios including the cookie round-trip (`h2_hpack_stress_qemu.py`), both GOAWAY scenarios (`h2_goaway_qemu.py`), and real nginx interop (`h2_nginx_interop_qemu.py`); the full existing host suite, `h2-fuzz`, and a broad QEMU regression sweep (including `keepalive_qemu.py`, since the `net/tcp.c` fix touches code shared by every TCP connection Aurora ever makes, not just h2) all re-verified unaffected | ✅ |

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

## Step 17.1.3 — a real HEADERS frame, HPACK static table only

17.1.1 and 17.1.2 proved the h2 *connection* works. This phase proves
Aurora can send a real *request* over it — the difference between "we can
speak the protocol's opening handshake" and "we can actually ask a server
for something." What it deliberately still can't do is understand the
answer: RFC 7541's static table has no *value* for most response headers
(`date`, `server`, `content-length`, ...), so a real encoder almost always
falls back to literals, frequently Huffman-coded — and Aurora has neither
Huffman nor a dynamic table yet. That's 17.2/17.3's job. This phase's
job is narrower and, on its own terms, complete: build a genuinely
correct, static-table-only HPACK request a real server accepts.

**`http2/hpack.c`** implements exactly what that needs: RFC 7541 §5.1's
prefixed-integer encoding (verified directly against the RFC's own worked
example — 1337 with a 5-bit prefix encodes to `1f 9a 0a`, and `hpack_put_int()`
produces exactly that), §5.2's string literals (length-prefixed, Huffman
bit always clear — Huffman is optional for a sender, and decoding it is a
decode-side problem this phase doesn't have), and two of RFC 7541 §6's
representations: "Indexed Header Field" (§6.1, both name and value from
the static table) and "Literal Header Field *without* Indexing" (§6.2.2).

That second choice is deliberate, not incidental: RFC 7541 also defines
"Literal Header Field *with Incremental Indexing*" (§6.2.1), which tells
the peer's decoder to add the entry to *its own* dynamic table. Using it
would be free short-term (nothing about sending it requires Aurora to
track anything), but a correctness trap for the future — Aurora doesn't
mirror a dynamic table of its own, so on a hypothetical second request
reusing this connection, it would have no way to know what index numbers
the server's dynamic table now has occupied, and any future dynamic-table
use (17.2) would risk colliding with entries the peer thinks it already
agreed to. "Without indexing" has no such implication: it explicitly
tells the peer not to add the entry, so nothing needs to stay in sync.

**`http2/headers.c`** (`h2_build_headers()`) assembles a real request
from this: `:method` is indexed when it's the static table's own GET/POST
value, otherwise a literal using GET's index for the name; `:scheme` is
always `https` (this client only ever reaches h2 over TLS) and always
indexed; `:path` is indexed only for the literal root `/`; `:authority`
and `user-agent` are always literals (the static table has no fixed value
for either — every real host differs, and there's no single "the"
user-agent). `h2_send_request()`, in `user/httpsget.c`, calls this once
`h2_handshake()` succeeds, sends the result opening stream 1 (RFC 7540
§5.1.1's first client-initiated stream ID), then waits for one response
frame and names it by type only — still not decoding it — before
`fetch_begin()` ends the connection attempt either way, now for a more
specific and more honest reason than before: not "no HEADERS framing",
but "response decoding needs Huffman/the dynamic table."

Verified two ways:
- **Host (`make h2-test`)**: 22 new cases. The RFC 7541 §5.1 pin above,
  plus indexed/literal representations checked individually (including
  the multi-byte continuation case: static table index 58, user-agent,
  doesn't fit a 4-bit prefix's 15-value max, so it needs a second byte —
  `0f 2b`, confirmed byte-for-byte). Then four complete HEADERS frames —
  a plain `GET /`, a `GET` with a real path plus a user-agent (exercising
  that same multi-byte index in a full frame, not just in isolation),
  `POST`, and `PUT` (the one case exercising a literal `:method`, since
  PUT has no static-table value) — each checked against a full hex byte
  sequence hand-derived directly from RFC 7541's encoding rules, not
  copied from anywhere. Writing these caught a real bug, in the *test*:
  a user-agent string literal's length was hand-counted one byte too
  long, so the encoder faithfully copied the C string's own NUL
  terminator in as if it were data — `http2/hpack.c` had done exactly
  what it was told; the check simply proved the *told* was wrong, exactly
  the kind of transcription slip this project has hit before with hex
  constants, caught the same way: a precise byte-level check, not eyeballing.
  The full existing host suite passes unchanged.
- **QEMU (`tools/h2_handshake_qemu.py`, extended)**: a genuine, from-scratch
  Python HPACK *decoder* — independent of `http2/hpack.c`, and of any
  third-party package (this session tried `pip install hpack` as a
  reference and the action was correctly denied by this environment's own
  permission policy, since an undeclared external dependency is exactly
  the kind of thing that policy exists to catch — the from-scratch
  approach turned out to be the right call anyway, matching how this
  suite's own frame encoder was already built independently of Aurora's).
  The test server receives Aurora's real HEADERS frame and decodes
  `:method=GET`, `:scheme=https`, `:authority=10.0.2.2`, `:path=/whatever`,
  and Aurora's own user-agent string — the actual values from the actual
  request, not placeholders — then answers with a real, minimal (single
  indexed byte) `:status: 200` HEADERS frame, which Aurora's log confirms
  it recognized by type without decoding it. All 23 checks pass. Because
  this reaches further into `fetch_begin()`'s h2 path than 17.1.2 did,
  this phase repeats the full 13-script QEMU regression sweep end to end
  — all pass unaffected.

## Step 17.2.1 — HPACK Huffman decoding

17.1.3 could build a real request but not read a real response: RFC 7541's
static table has no *value* for most response headers (`date`, `server`,
`content-length`, ...), so a real server's HEADERS frame almost always
carries literal strings, and those are frequently Huffman-coded — a real
encoder chooses whichever representation is shorter, and Huffman-coded
text almost always is. Aurora's own encoder still never produces one (that
choice, made in 17.1.3, doesn't change here — see below), but reading one
back is unavoidable if Aurora is ever going to understand what a real
server actually said. That's this phase's entire scope: decode-only.

**`http2/huffman.c`** implements RFC 7541 §5.2's Huffman coding as a
bit-by-bit canonical-code walk: read one bit at a time into a candidate
`(code, len)` pair and, after every bit, scan the table's 256 real symbols
for an exact match (never matching symbol 256 — EOS — itself, since RFC
7541 §5.2 forbids a sender from ever encoding it; the prefix-free property
of a canonical Huffman code means a genuine attempt to smuggle EOS mid-stream
just runs past every real code's maximum length instead of matching
anything, which is exactly the `len > 30` rejection path). Whatever bits
are left over at the very end (0-7 of them, padding to a whole byte) must
themselves be a prefix of EOS's own code — which is 30 consecutive 1-bits —
so valid padding is always all-1s; anything else is rejected as corrupt
input, not silently accepted.

The one architectural decision worth calling out explicitly: **only
decode.** There is no `hpack_huffman_encode()`, and `http2/hpack.c`
(17.1.3) is untouched by this phase. This isn't an oversight — RFC 7541
§5.2 makes Huffman coding optional for a sender, and Aurora's own encoder
already made that call in 17.1.3 for a specific reason (avoiding any
dynamic-table synchronization risk with Aurora's Keep-Alive/Session
Resumption/Multi-Origin Session Cache design). Decoding is a fundamentally
different, one-directional problem: RFC 7541 §2.3.2 is explicit that the
encoding and decoding dynamic tables (and, by the same logic, Huffman
usage) on the two sides of a connection are entirely independent of each
other. Understanding what a real server chooses to send back carries none
of the synchronization risk that sending Huffman-coded requests would —
it's a pure decode-side capability addition, not a protocol behavior
change on Aurora's own send path.

The 257-entry canonical code table (256 symbols + EOS) behind the decoder
was **not hand-transcribed from RFC 7541 Appendix B.** This project has
hit exactly that class of error before — the gzip/CRC32/inflate known-answer
vectors in 15.10, and even a hand-counted user-agent string length in
17.1.3's own test, caught only because a byte-level check flagged the
mismatch — and a 257-entry bit-exact table is a much larger target for the
same mistake. Two AI-assisted shortcuts were considered and rejected:
`WebFetch` was ruled out because its own documentation says large content
"may be summarized" by an intermediate model before being returned — an
unacceptable risk when the whole point is avoiding a transcription
intermediary between the RFC's own numbers and the C source; `pip install
hpack` (an existing third-party Python package with an HPACK-derived
table available) was correctly denied by this environment's own permission
policy as an undeclared external dependency, the same call it made when
17.1.3 tried it for a different reason. Instead: `curl` fetched the RFC's
raw plaintext directly (`https://www.rfc-editor.org/rfc/rfc7541.txt`, no
summarization layer in between), a narrow regex script mechanically parsed
all 257 `(symbol, code, length)` triples out of Appendix B's own text, and
the parse's own correctness was verified two ways before any C was written:
completeness (257/257 entries found, no duplicates, no gaps) and three spot
checks against values the RFC itself documents inline (symbol 47 `/` →
`0x18` at 6 bits, symbol 0 → `0x1ff8` at 13 bits, EOS → `0x3fffffff` at 30
bits — all exact). The decode *algorithm* itself was then separately
prototyped in Python and run against RFC 7541 Appendix C.4's own two
worked Huffman examples before the C implementation existed, so a bug in
the algorithm's logic couldn't hide behind a bug in the table, or vice
versa — the same "independent second implementation" discipline this
session's QEMU test server has used for its own frame/HPACK code since
17.1.1.

Verified two ways:
- **Host (`make h2-test`)**: 11 new cases. RFC 7541 Appendix C.4.1
  (`f1e3c2e5f23a6ba0ab90f4ff` → `"www.example.com"`) and C.4.2
  (`a8eb10649cbf` → `"no-cache"`) — the RFC's own published worked
  examples, not independently invented vectors — both decode byte-for-byte
  correct. Plus edge cases the RFC vectors alone don't exercise: an empty
  input decodes to an empty string rather than erroring; a single `0x00`
  byte decodes one real symbol (`'0'`, the shortest 5-bit code) and then is
  correctly rejected for invalid, non-all-1s padding, rather than silently
  truncating the leftover bits; four bytes of `0xff` (a run of 1-bits
  longer than any real symbol's code, running straight past even EOS's own
  30-bit length) is rejected outright rather than ever being treated as a
  decoded EOS; and decoding into a deliberately undersized output buffer
  fails loudly instead of truncating. The full existing host suite,
  including every prior `h2-test` case, passes unchanged.
- **QEMU**: not yet exercised end-to-end — this phase is explicitly scoped
  as a standalone decode capability, not wired into `httpsget.c`'s live h2
  response path yet, since a real response also needs the dynamic table
  (17.2.2) before decoding it end-to-end means anything. Because
  `http2/huffman.c` is a new, purely additive object file (linked into
  `httpsget.elf`'s build but not yet called from any code path), the full
  16-script QEMU regression sweep — every `tools/*_qemu.py` script,
  including `h2_handshake_qemu.py` itself — was re-run in full to confirm
  byte-identical externally observable behavior. All pass unaffected.

## Step 17.2.2 — HPACK dynamic table + full header block decode

17.2.1 gave the decoder a way to read Huffman-coded strings; this phase
gives it everything else HPACK's compression model depends on. RFC
7541's dynamic table (§2.3.2) is what makes HPACK actually *compress*
across a connection, not just per-message: a header seen once can be
referenced by a one-byte index on every later message, as long as both
sides track the same table. Without it, 17.1.3/17.2.1's decoder could
read a single isolated HEADERS frame, but not a real connection's worth
of them — and a real connection is exactly what Aurora needs to read.

**`http2/hpack_table.c`** holds two tables behind one unified index space
(RFC 7541 §2.3.3): the 61-entry static table (Appendix A — mechanically
extracted the same way as 17.2.1's Huffman table, with each string's
length computed by the compiler via `sizeof(x) - 1` rather than hand-
counted, closing off the exact class of mistake that produced a hand-
counted user-agent length bug in 17.1.3), and a dynamic table this
decoder builds up itself as it processes what a peer's encoder sends. The
dynamic table is a fixed 4096-byte arena, not a dynamic allocator (this
directory's established convention for large structures — `static`
globals sized for the worst case), sized to exactly the RFC 7540 §6.5.2
default `SETTINGS_HEADER_TABLE_SIZE` that applies as long as Aurora's own
SETTINGS frame stays empty: no peer behaving legally can ever ask this
decoder to hold more than that. Insertion (§6.2.1's side effect) evicts
the oldest entries as needed to stay under the current max size, oldest-
first, per §4.1's accounting rule (name + value + 32 bytes of overhead
per entry); a Dynamic Table Size Update (§6.3) changes that max and
evicts down to fit; an entry larger than the max size, even once the
table is emptied trying to make room, is simply not stored (§4.4) without
that being treated as an error.

**`http2/hpack_decode.c`** adds §5.1's prefixed-integer decode and §5.2's
string-literal decode (raw or Huffman, via `huffman.c`), then dispatches
every §6 representation a real header block can contain — Indexed Header
Field, Literal with Incremental Indexing (the only one that grows the
table), Literal without Indexing, Literal Never Indexed, and Dynamic
Table Size Update — into a caller-supplied array of decoded header
fields. Aurora's own encoder (`hpack.c`, 17.1.3) is untouched, deliberately:
RFC 7541 §2.3.2 makes the two directions' dynamic tables entirely
independent of each other, so tracking what a *peer's* encoder chooses to
do carries none of the send-side synchronization risk that motivated
17.1.3's own choice to never use incremental indexing when Aurora sends.

Writing the tests surfaced a real, working-code bug before any of this
ever shipped: the decoder's first draft returned raw pointers into the
dynamic table's own byte arena for anything resolved by index. That's
fine in isolation, but a *later* representation within the same header
block can trigger an eviction — which compacts the arena, shifting bytes
— and an *earlier* representation's already-decoded field, if it also
came from the dynamic table, would silently point at whatever now occupies
that shifted memory. This isn't a hypothetical: RFC 7541's own Appendix
C.5.3 worked example does exactly this (a `cache-control` entry read
early in a response is evicted later in that very same response) — which
is how the test written directly from that example caught it. The fix:
every byte range this decoder ever hands back to a caller — including
ones resolved *from* the dynamic table, not just freshly-decoded literals
— is copied into the caller's scratch buffer immediately upon resolution,
before any later representation in the block gets a chance to mutate the
table out from under it.

Verified against RFC 7541's own multi-step, multi-request/response
sequences — not self-invented ones, since those are exactly what this
phase's dynamic-table bookkeeping needs exercised, and the RFC publishes
its own expected intermediate table state after each step to check
against:
- **Host (`make h2-test`)**: 86 new cases. The four isolated representation
  examples (Appendix C.2.1-C.2.4: literal with incremental indexing,
  literal without indexing, literal never indexed, indexed header field).
  The full three-request sequence from Appendix C.3, decoded through the
  *same* table instance across all three calls, checking not just the
  decoded fields but the table's own entry count and byte size against
  the RFC's documented state after each request — including a dynamic
  entry referenced back by index 62 in request 2, then by index 63 in
  request 3 once a second insertion pushes it one further back (RFC
  7541's own worked example of "Indexed Dynamic Entries" from the
  roadmap). The full three-response sequence from Appendix C.5, with
  `SETTINGS_HEADER_TABLE_SIZE` set to 256 exactly as the RFC specifies,
  to force real evictions — including the third response, the exact case
  that caught the arena-aliasing bug above. `Dynamic Table Size Update`
  exercised directly (shrinking evicts down to what fits, down to and
  including fully emptying the table) and inline within a real header
  block. Malformed input rejected without corrupting state: an indexed
  field past the last live entry, index 0 (RFC 7541 §6.1's "MUST treat as
  a decoding error"), a size update past the 4096-byte arena cap, a
  string literal whose declared length runs past the input, an output
  array too small for even one field, and a scratch buffer too small for
  one decoded string. The full existing host suite passes unaffected.
- **QEMU**: not yet exercised end-to-end — still not wired into
  `httpsget.c`'s live h2 response path; assembling a decoded header block
  into an `http_response`-shaped result, and reading the DATA frame(s)
  that follow it, is Phase 17.3. `http2/hpack_table.c`/`hpack_decode.c`
  are new, purely additive object files (linked into `httpsget.elf` but
  not yet called from any code path), so the full 16-script QEMU
  regression sweep — every `tools/*_qemu.py` script — was re-run in full
  to confirm byte-identical externally observable behavior. All pass
  unaffected.

## Step 17.3 — the first genuinely complete HTTP/2 response

By 17.2.2, every building block for a real HTTP/2 fetch existed: ALPN
negotiation, the connection-establishment handshake, a generic frame
reader, a DATA frame parser, an HPACK-compressed HEADERS builder, and a
complete HPACK decoder (Huffman, the full static table, and a decode-side
dynamic table). What was still missing was purely the wiring between them
and the rest of the client. 17.3 is deliberately just that: no new
protocol capability, only integration -- read stream 1 to completion,
decode what comes back, and hand it to the exact same code that already
knows how to print an HTTP/1.1 response.

**The design goal, stated by the user before this phase started**: don't
invent a separate "HTTP/2 response" representation. `struct http_response`
(`user/http.h`) and the `g_resp`/`g_hr`/`g_body` globals it's built from
already do everything a response needs to carry -- status, headers, body.
An h2 response should produce exactly the same thing an HTTP/1.1 response
does, so nothing above `fetch_request()` ever needs a protocol-specific
branch.

**How that's achieved**: `h2_synthesize_header_block()`
(`user/httpsget.c`) translates a decoded HPACK header-field list into an
HTTP/1.1-shaped status-line-plus-headers text block -- literally
`"HTTP/1.1 200 (via HTTP/2)\r\n..."` followed by `"name: value\r\n"` lines
for every regular header, ending in the usual blank line. That text,
together with each DATA frame's payload, is fed through the pipeline's
own existing `resp_feed()` -- the very function an HTTP/1.1 response's
decrypted bytes already flow through. `resp_feed()` calls `http_parse()`
(`user/libc/http.c`, unmodified) on it, which is where `g_hr.status`,
`content_type`, `location`, `gzip`, and `keep_alive` all get populated --
and since `http_parse()` doesn't know or care whether its input arrived
over TCP+HTTP/1.1 or was synthesized from a decoded h2 header list, none
of that logic needed to change. Set-Cookie parsing (`http_find_header()`
scanning `g_resp` directly), gzip streaming (`feed_gzip()`, triggered by
`http_parse()` seeing `content-encoding: gzip`), and the body-preview
printing in `fetch_one()` all inherit the same "it just works" property
for exactly the same reason.

One line in the synthesized block carries real design weight: `h2_fetch()`
always appends `Connection: close`, regardless of what the peer actually
sent. RFC 7540 §8.1.2.2 forbids HTTP/1.1's connection-specific headers
(`connection`, `transfer-encoding`, `keep-alive`, `upgrade`) over h2
entirely, and this client doesn't reuse an h2 connection for a second
stream yet (that's a natural follow-up, not attempted here) -- so forcing
this line makes `http_parse()`'s own existing keep-alive computation come
out false, which makes the *existing* `reusable()`/`slot_close()` logic in
`fetch()`/`fetch_one()` already close the connection after its one
response, with zero h2-specific code of its own. A `session_slot` gained
exactly two new fields for this: `is_h2` (freshly determined by
`fetch_begin()` on every connection attempt) and `h2_dyn_table`, the
connection's own persistent HPACK decode-side dynamic table (RFC 7541
§2.3.2 -- a fresh TCP connection always starts a fresh compression
context, so this is re-initialized every time `is_h2` is set).

**A defensive line worth calling out**: `h2_text_safe()` rejects any
decoded header name or value containing a CR or LF byte (or, for a name
specifically, a `:`) before it's spliced verbatim into the synthesized
text. Aurora's own HPACK decoder (17.2.1/17.2.2) only knows how to decode
*bytes* correctly -- it doesn't enforce HTTP's own field-name/value
syntax, which is a decode-independent semantic layer on top. Without this
check, a malicious server could HPACK-encode a header value containing an
embedded `\r\n` and inject an extra header line, or corrupt the
synthesized blank-line boundary, into text this client's own trusted
HTTP/1.1 parser is about to consume -- the HTTP response-splitting
vulnerability class, reproduced at the translation boundary between two
representations Aurora itself controls. Any response failing this check
is rejected outright (decode failure, matching hpack_decode.h's own "a
malformed block is unrecoverable for the rest of the connection"
contract), not silently sanitized.

Verified two ways:
- **Writing the acceptance test caught a real bug before this ever
  shipped**: the first draft had `h2_fetch()` fill `*out` and return
  `FETCH_OK` directly, which skipped straight past `fetch_request()`'s
  own Set-Cookie-scanning tail -- code that's *shared* between the
  HTTP/1.1 and h2 paths, but only runs *after* the branch that decides
  which one to take. An h2 response's Set-Cookie header was silently
  never stored. The QEMU test below caught this immediately (one failing
  check out of 25). Fixed by having `h2_fetch()` return only a `closed`
  flag and restructuring `fetch_request()` so the *existing* shared tail
  (staleness check, Set-Cookie scan, `*out` fill) runs unchanged
  regardless of which branch executed -- the same "reuse, don't
  duplicate" discipline this whole phase is built on, this time enforced
  by a real integration test rather than caught by inspection.
- **QEMU (`tools/h2_handshake_qemu.py`, extended a fourth time)**: the
  same real, independent, from-scratch Python HTTP/2+HPACK server this
  script has used since 17.1.1 now sends back a REAL response instead of
  a single indexed byte: a HEADERS frame using "Literal Header Field with
  Incremental Indexing" (RFC 7541 §6.2.1) for `:status`, `content-type`,
  and `set-cookie` -- each an indexed NAME with a literal value, so
  Aurora's decode-side dynamic table genuinely grows during this test,
  not just against the 17.2.2 host tests' own RFC vectors -- plus one
  fully literal name+value header, followed by THREE DATA frames chosen
  to cover every item on this phase's own DATA checklist in one response:
  a real multi-frame sequence, a zero-length frame in the middle, padding
  on the last frame, and `END_STREAM` on it. All 25 checks pass: Aurora's
  own log shows the HEADERS frame HPACK-decoded (4 fields), the
  synthesized `HTTP/1.1 200 (via HTTP/2)` status line, `status=200`
  actually reached, the real page text from the DATA frames (not a
  placeholder), the decoded Set-Cookie stored, and the familiar `200 OK
  over Aurora TCP->TLS1.3->HTTP` closing line -- the exact same output
  shape an HTTP/1.1 fetch produces. The server independently confirms the
  connection closes cleanly afterward with nothing further sent, proving
  no second stream or keep-alive reuse was attempted. Because this phase
  changes *shared* code in `fetch_request()` (not just new, still-unused
  files, as 17.2.1/17.2.2 were), the full 16-script QEMU regression sweep
  was re-run in full rather than assumed unaffected -- all pass with
  byte-identical HTTP/1.1 behavior.

With this, Aurora's transport stack finally has the shape the user
described at the start of the 17.x series: TLS → ALPN → HTTP/1.1 *or*
HTTP/2, converging on the same `http_response` the rest of the client
(gzip, cookies, redirects, keep-alive, POST) already knows how to use.
Deliberately still out of scope, left for later, natural follow-up
phases: an h2 request carrying a method other than GET or a request body,
reusing one h2 connection across more than one stream, and any of
PRIORITY/PUSH_PROMISE/CONTINUATION/real flow-control -- "HTTP/2 v2"
territory this phase never needed for its own goal.

## Step 17.4.1 — HTTP/2 request bodies, full 16.5 `--method` parity

With 17.3, HTTP/2 could carry exactly one shape of request: a bodyless
GET. Every other method the 16.5 HTTP/1.1 path already supports --
HEAD, OPTIONS, DELETE, POST, PUT, PATCH -- was unreachable over h2, since
`h2_fetch()` hardcoded `"GET"` and `h2_build_headers()` had no way to
express a body at all. This phase closes that gap, purely by extending
the same two functions 17.1.3/17.3 already built -- no new frame types,
no new HPACK representations, no new response handling.

**`http2/headers.c`**: `h2_build_headers()` gains `content_type`/
`content_type_len`/`body_len` parameters. When `body_len > 0`, two more
headers are appended the same way `:authority`/`user-agent` already are
-- "Literal Header Field without Indexing" against an indexed NAME
(Content-Type is static-table index 31, Content-Length is index 28, both
name-only entries) -- and END_STREAM is cleared on the HEADERS frame
(the caller now owes a DATA frame). Content-Length's *value* is always
`put_udec(body_len)`, a small freestanding decimal formatter -- never a
separately-passed number that could silently drift from what the caller
actually sends in the DATA frame that follows. Every existing caller
(the 17.1.3 host tests, `h2_fetch()`) needed `0, 0, 0` added for the
three new parameters; passing zeros for all three reproduces the exact
prior behavior byte-for-byte, re-verified directly (see below).

**`user/httpsget.c`**: `h2_fetch()` now takes the same `method`/`body`/
`bodylen`/`content_type` `fetch_request()` already threads through for
the HTTP/1.1 path, instead of hardcoding GET, and builds the HEADERS
frame followed by one `h2_data_build()` DATA frame (END_STREAM on it
instead) whenever `bodylen > 0` -- both sealed and sent as a single TLS
write, matching how `build_request()`'s own HTTP/1.1 request is already
one buffer, one seal, one write. `content_type` defaults to
`application/x-www-form-urlencoded` when the caller didn't supply one,
mirroring `build_request()`'s own default exactly. `POST_BODY_MAX`
(4096 bytes) fits comfortably in a single DATA frame (well under
`H2_FRAME_PAYLOAD_MAX`), so there's no need to split a request body
across frames the way a large *response* body naturally arrives split
across several.

Because `resp_reset(method)` (not a hardcoded `"GET"`) now runs for
every h2 request, this phase is really "full `--method` parity," not
just "POST/PUT/PATCH": a `--method HEAD` request negotiated over h2
correctly suppresses the response body per RFC 7230 §3.3.3's own rule
(already reused unchanged from the HTTP/1.1 path, exactly the kind of
free win the "one API" design keeps producing).

Deliberately still out of scope: reusing one h2 connection across more
than the single request/stream this phase (and 17.3 before it) always
opens and closes, and an Authorization header over h2 -- both natural
follow-ups, neither needed for request bodies to work correctly today.

Verified two ways:
- **Host (`make h2-test`)**: 11 new cases. A POST with a 13-byte body,
  its expected HPACK bytes computed by a small from-scratch Python
  encoder mirroring `hpack_put_int()`'s own algorithm (this project's
  standing discipline of never hand-deriving a longer hex vector by
  eye, applied here since Content-Type/Content-Length's multi-byte
  index continuations make this the longest single vector in the file)
  -- END_STREAM clear on HEADERS, the Content-Type/Content-Length bytes
  exactly right. The paired DATA frame, built and checked separately
  (END_STREAM set, length and bytes matching the real body exactly). A
  bodyless GET re-checked against 17.1.3's own *original* hex vector,
  byte-for-byte -- proving the new parameters produce zero drift for
  the case that doesn't use them.
- **QEMU (`tools/h2_post_qemu.py`, new)**: mirroring how 16.1's own POST
  support got a dedicated `post_qemu.py` rather than continuing to grow
  an already-large shared script, this test runs `httpsget --alpn
  --method POST` against a real, independent, from-scratch Python
  HTTP/2+HPACK server and confirms: END_STREAM is clear on the request's
  HEADERS frame; the server's own HPACK decoder extracts `:method: POST`
  and a real Content-Type; Content-Length matches the *real* body length,
  not a placeholder; END_STREAM is set on the DATA frame that follows,
  and its payload is the exact real body bytes; and -- proving the two
  directions genuinely don't interfere on the same stream -- Aurora's
  read path still reaches `status=200` immediately after having just
  sent that body-bearing request. All 18 checks pass. Full existing host
  suite and the complete 17-script QEMU regression sweep (16 prior
  scripts plus this new one) pass unaffected.

## Step 17.4.2 — HTTP/2 connection reuse (sequential streams, no multiplexing)

Every h2 fetch through 17.4.1 opened a fresh TCP+TLS connection, sent
exactly one request, read exactly one response, and closed -- even when
the very next line of a multi-path `httpsget` run was going back to the
same host a moment later. HTTP/1.1 keep-alive (15.4) had already solved
this for the older protocol; h2 paid for a full handshake every single
time regardless. This phase closes that gap the same way 17.3 closed
"HTTP/2 can't produce a usable response" -- by making the *existing*
machinery (`session_slot`, `reusable()`, `slot_close()`) do the right
thing for h2 too, not by inventing a parallel one.

**Stream numbering.** RFC 7540 §5.1.1 requires client-initiated stream
IDs to be odd and strictly increasing for the life of a connection --
1, 3, 5, .... `session_slot` gained `next_h2_stream`, reset to 1 every
time `fetch_begin()` establishes a fresh h2 connection (right alongside
`h2_dyn_table`'s own re-initialization, since both are properties of
*this* connection's context, not the client as a whole) and incremented
by 2 at the top of every `h2_fetch()` call, which now builds its request
on `stream_id` instead of a hardcoded `1`.

**Why the dynamic table needed no changes at all.** `h2_dyn_table` was
already a `session_slot` field, already persistent for the connection's
lifetime -- it just never got the chance to matter beyond one request
before, since the connection never lived past one. RFC 7541 §2.3.2's own
model (one compression context per connection, not per stream) means
"decode-side HPACK correctness across a *sequence* of requests" was
already fully proven at the unit level back in 17.2.2, against the RFC's
own Appendix C.3/C.5 multi-message sequences. This phase's own job was
purely to give that existing correctness a real second request to prove
itself against over the wire.

**Why `Connection: close` had to go, and what replaced it.** 17.3 forced
a synthesized `Connection: close` line into every h2 response's
translated text specifically so `http_parse()`'s own keep-alive
computation would come out false, since nothing else was there to say
"don't reuse this." Now that reuse is the goal, that line is simply
removed -- and `fetch_request()`'s h2 branch sets `g_hr.keep_alive`
*directly* from `h2_fetch()`'s own return value: 1 if the stream's real
END_STREAM arrived (a genuinely complete exchange), 0 otherwise. This is
a deliberate, explicit override, not a hope that `http_parse()`'s
HTTP/1.1-shaped heuristic would happen to land on the right answer --
because it wouldn't, reliably: `http_parse()` only ever considers
`keep_alive` true when `content_length >= 0`, but a real h2 response
routinely omits Content-Length entirely (framing plus END_STREAM already
delimits the body; nothing in HTTP/2 needs the header the way HTTP/1.1
does). Left alone, `http_parse()` would silently mark most real h2
responses non-reusable regardless of whether they actually were.

**Why `reusable()`'s size cap needed a matching fix.** `FETCH_REUSE_MAX_BODY`
exists to answer one specific HTTP/1.1 question: "is it worth draining
the rest of a large body just to reach a clean reuse boundary?" -- a real
choice for HTTP/1.1, where `fetch_request()`'s read loop can and does stop
early at the preview cap instead of draining, when reuse isn't going to
happen anyway. That choice doesn't exist for h2: `h2_fetch()` always reads
a stream to its own real end (END_STREAM) as an unavoidable part of
getting the response AT ALL -- there's no "drain or don't" fork to weigh a
size against. `reusable()` gained a `content_length < 0` fast path
(reusable with no size check) to reflect this -- provably a no-op for
every prior HTTP/1.1 call site, since `http_parse()` itself never sets
`keep_alive` true when `content_length` is -1, so the new branch is simply
unreachable from that direction.

**A real bug the reuse scenario exposed.** `h2_fetch()`'s read loop used
to stop draining a decrypted TLS-record chunk (`g_plain`) the instant the
current stream's own `stream_ended` flag went true partway through it --
correct enough when the connection was about to be closed moments later
regardless (17.3/17.4.1), but silently wrong once the connection needed
to stay usable: any trailing bytes past that point (a connection-level
`WINDOW_UPDATE` the server happened to send right behind its response,
for instance) were simply discarded, since `g_plain` gets overwritten on
the next decrypt call. Fixed by draining every decrypted chunk fully
regardless of `stream_ended`, only skipping *acting* on further frames
once the current stream is already known complete -- no bytes left
behind for the next `h2_fetch()` call to never see.

Verified against a scenario specifically designed to make a
still-wrong implementation fail loudly:
- **QEMU (`tools/h2_reuse_qemu.py`, new)**: `httpsget --alpn 10.0.2.2 /a
  /b` against a real, independent, from-scratch Python HTTP/2+HPACK
  server that accepts **exactly one** TCP connection for both requests
  (a second `accept()` would mean Aurora silently reconnected instead of
  reusing -- the one failure mode this whole phase exists to prevent).
  The first response adds `:status`/`content-type` to its own dynamic
  table via "Literal Header Field with Incremental Indexing"; the SECOND
  response -- on the same connection, stream 3 confirmed instead of
  another stream 1 -- answers using **pure "Indexed Header Field"
  references** into those same two entries, zero literal bytes for
  either header. This only decodes correctly if Aurora's own
  `h2_dyn_table` genuinely survived from the first request to the
  second; if it had been reset (the bug this phase's design specifically
  avoids), HPACK decode would fail outright and Aurora's log would show
  a decode-error diagnostic instead of a real response. All 20 checks
  pass: one connection, correct stream IDs (1 then 3), both distinct
  response bodies received intact, Aurora's own log showing "reusing
  open connection to 10.0.2.2" (not a second TLS handshake), both
  requests reaching `status=200`. Full existing host suite and the
  complete 18-script QEMU regression sweep -- with particular attention
  to `keepalive_qemu.py`, since this phase edits `reusable()`, code
  shared with HTTP/1.1's own keep-alive path -- all pass unaffected.

## Step 17.4.3 — minimal HTTP/2 flow control (one active stream's worth)

Every earlier h2 phase had an unstated assumption baked in: the response
would be small enough to arrive before anyone noticed flow control wasn't
implemented at all. RFC 7540 §6.9's default window -- 65535 bytes, both
per-stream and per-connection -- is generous for a status line and a
short JSON body, but a real page (or, more mundanely, this project's own
`docs/SECURITY.md`) clears it easily. Without a receiver replenishing its
window, a spec-compliant server simply stops sending once it believes the
window is exhausted -- correctly, from its side -- and a client that never
says otherwise just hangs. This phase closes that gap, and closes the
17.4 series the roadmap laid out: request bodies (17.4.1), connection
reuse (17.4.2), and now flow control complete "an HTTP/2 client
practically usable for real fetches," not just capable of a demo.

**Two windows, one stream.** RFC 7540 §6.9 tracks flow control at two
scopes simultaneously: one shared window for the whole connection, and
one independent window per stream. `session_slot.h2_conn_recv_window`
holds the connection-level one -- reset to `H2_INITIAL_WINDOW_SIZE`
(65535) only when `fetch_begin()` establishes a fresh h2 connection,
alongside `h2_dyn_table`/`next_h2_stream`, so it correctly spans however
many sequential requests 17.4.2 lets that connection carry. The
stream-level window doesn't need slot-level persistence -- RFC 7540
itself resets it fresh for every new stream -- so it's just a local
variable in `h2_fetch()`, reinitialized on entry.

**Why no `SETTINGS_INITIAL_WINDOW_SIZE` parsing was needed.** This
setting, when a peer sends it, only ever describes *that peer's own*
receive-side window for the direction pointed *at* them -- it doesn't
tell the other side what window to use for receiving. Aurora's own
advertised window (the one this phase's whole `h2_conn_recv_window`/
stream-window accounting exists to enforce and replenish) is governed
entirely by what Aurora itself put in *its own* SETTINGS frame -- which
has stayed empty since 17.1.1, meaning the RFC 7540 §6.5.2 default
always applies. The server's own advertised window (via its SETTINGS)
would matter if Aurora needed to gate *its own sends* on it -- but as the
next paragraph explains, that never happens here, so there was nothing
to parse.

**Deliberately not gating sends.** Incoming WINDOW_UPDATE frames from the
server are fully recognized and validated (`h2_window_update_parse()`
rejects a payload that isn't exactly 4 bytes, or the zero increment RFC
7540 §6.9 calls out as a required rejection), printed as a diagnostic --
but the numeric value is never used to decide whether Aurora is "allowed"
to send its own request body yet. `POST_BODY_MAX` caps every request
body Aurora can construct at 4096 bytes, and the RFC 7540 §6.5.2 default
window (65535) is more than 16x that -- there is no real server
configuration where Aurora's own tiny body would ever need to wait for
room. Building genuine send-side gating (tracking a "how much can I send
right now" counter, blocking or retrying when it's insufficient) would be
real, non-trivial complexity in service of a wait that can provably never
happen -- exactly what the project's own "no fallbacks for scenarios that
can't happen" discipline argues against building.

**A concrete failure this phase makes real instead of theoretical.** A
window going negative -- the server having sent more DATA than Aurora
ever authorized -- is treated as a hard protocol violation, aborting the
request, the same "fail loudly on a peer exceeding what it was told"
posture already applied throughout `http2/`'s decode paths (HPACK, frame
size, DATA padding). Silently tolerating it would mean accepting an
accounting Aurora itself can no longer trust for the rest of the
connection.

Verified two ways:
- **Host (`make h2-test`)**: 15 new cases for `http2/window_update.c` --
  `h2_window_update_build()`/`h2_window_update_parse()` round-tripping
  both a connection-level (stream 0) and a stream-level frame, the
  reserved top bit (RFC 7540 §6.9: "MUST be ignored on receipt") not
  corrupting the 31-bit increment when a peer sets it, and rejection of a
  zero increment, an out-of-31-bit-range increment, an undersized output
  buffer, and a payload that isn't exactly 4 bytes.
- **QEMU (`tools/h2_flowctl_qemu.py`, new)**: `httpsget --alpn 10.0.2.2
  /big` against a real, independent, from-scratch Python HTTP/2 server
  answering with a 200000-byte body -- forced by the 16384-byte
  `H2_FRAME_PAYLOAD_MAX` cap into 13 separate DATA frames, comfortably
  clearing the default 65535-byte window multiple times over. The server
  confirms it received BOTH a connection-level and a stream-level
  WINDOW_UPDATE from Aurora, more than one of each over the transfer, and
  every increment RFC-plausible; Aurora's own log reports receiving
  exactly `200000 body bytes` -- the real proof nothing was silently
  dropped or stalled at the flow-control layer, since a bug here would
  either hang the fetch (server stops sending, nothing else ever arrives)
  or under-report the byte count (data quietly lost). All 14 checks
  passed on the first run. Full existing host suite and the complete
  19-script QEMU regression sweep all pass unaffected.

With 17.4.3, Aurora's own roadmap for "a practically usable HTTP/2
client" is complete: ALPN, the connection-establishment handshake, a
generic frame reader, full HPACK (static table, Huffman, dynamic table),
GET through PATCH/DELETE/HEAD with real request bodies, connection reuse
across sequential requests, and now flow control for responses of any
realistic size. Multiplexing, PRIORITY, CONTINUATION, and PUSH_PROMISE
remain deliberately out of scope -- genuine "HTTP/2 v2" territory, not
needed for what this phase set out to prove.

## Step 17.5.1 — HTTP/2 hardening: fuzzing + sanitizer-enabled host testing

17.4.3 closed the last functional gap in "an HTTP/2 client practically
usable for real fetches." This phase opens a deliberately different kind
of series: not new RFC surface, but *evidence* that what's already built
actually holds up against input nobody hand-wrote. Every host test in
this project so far -- `h2-test` included -- checks known-good and
known-bad inputs the author chose. That's necessary, but it's a narrow
slice of "everything a real network peer could possibly send," and this
project's own history (the gzip/CRC32/inflate KATs in 15.10, a hand-
counted user-agent length in 17.1.3) already shows hand-chosen test
inputs miss things. Fuzzing and sanitizers are the tools for the part
hand-written tests structurally can't cover.

**`tools/h2_fuzz.c`** feeds random bytes -- some pure noise, some nudged
toward shapes likely to reach deeper code paths (a fraction of HPACK
blocks are biased toward the "Literal with Incremental Indexing, Huffman
bit set" shape, since uniformly random bytes mostly land on Indexed
Header Field and never reach the Huffman decoder at all) -- into six
targets: `hpack_decode_headers()`, the generic frame reader, `h2_data_parse()`,
`h2_settings_payload_valid()`, `h2_window_update_parse()`, and
`hpack_huffman_decode()` directly. A fixed default seed makes every run
reproducible; a failure prints the exact input bytes and the seed to
reproduce it, matching this project's own standing "never make a bug
report you can't hand someone else" discipline. Every call is checked
against its own documented output invariants, not just "did it survive"
-- a function that reads out of bounds without a sanitizer watching, or
that reports a byte count larger than the buffer it just filled, is
exactly the class of bug a plain crash-only fuzzer would walk right past.

**Sanitizers, and why GCC specifically.** `make h2-fuzz-san` and the new
`make h2-test-san` (the *existing* fixed-vector suite, rebuilt the same
way -- a nearly-free way to point far stronger instrumentation at tests
that already exist) both compile with `-fsanitize=address,undefined`.
This environment's `clang` has no sanitizer runtime library installed
(linking fails outright), while GCC's is present and works -- so, uniquely
among every host target in this Makefile, these two specifically invoke
`gcc`, not `$(CC)`. AddressSanitizer's stack/heap redzones and
UndefinedBehaviorSanitizer's runtime checks catch classes of bug that
"the program didn't crash" simply cannot rule out.

**Two real bugs, found within minutes of the harness actually running:**

1. **A genuine out-of-bounds read in `hpack_table_get()`**
   (`http2/hpack_table.c`) -- and a security-relevant one, since it's
   directly reachable from any HPACK-decoded HEADERS frame a real server
   sends. The bounds check read `if ((int)dyn_index >= t->count) return -1;`.
   `dyn_index` is `index - 62` (`unsigned`); RFC 7541 §5.1's own prefixed-
   integer encoding lets an index be anything up to `UINT32_MAX` without
   `hpack_get_int()`'s own overflow guard ever objecting -- there's
   nothing structurally wrong with a large index arriving on the wire.
   When `dyn_index` exceeds `INT_MAX`, casting it to `int` wraps to a
   *negative* number (implementation-defined in C, but universal
   two's-complement reinterpretation on every real platform) -- and a
   negative number is never `>= t->count`, so the bounds check silently
   passed, and `t->entries[dyn_index]` was read with `dyn_index` still
   holding its true, enormous, unsigned value. GDB confirmed the exact
   crash from the fuzzer's very first failing case: `hpack_table_get()`
   dereferencing memory far outside `t->entries[]`. Fixed by comparing
   entirely in unsigned arithmetic instead -- `dyn_index >= (unsigned)t->count`
   -- correct for literally every possible `index`, and no more expensive
   than the buggy version. This is exactly the outcome fuzzing exists to
   find: a real, network-triggerable memory-safety defect that eighteen
   prior phases of hand-written host tests and QEMU acceptance tests,
   run against real (if scripted) HTTP/2 servers, never happened to
   trigger, because no hand-chosen test vector ever contained an index
   anywhere near two billion.
2. **A stack buffer overflow in the test harness itself**, caught the
   moment `h2-test` was rebuilt under sanitizers. `tools/h2_test.c`'s
   `check_hex()` had used a bare `char hex[64]` with no capacity check
   since the very first version of this file (17.1.1); the 98-byte hex
   vector 17.2.2's own Appendix C.5.3 test introduced needs 197 bytes to
   render, silently overflowing the stack by 133 bytes on *every single*
   `h2-test` run since that commit -- passing every time regardless,
   since nothing observable ever happened to depend on whatever stack
   memory got clobbered, until ASan's redzones finally noticed. Fixed by
   widening the buffer and giving the underlying `tohex()` an explicit
   capacity parameter it now actually enforces, failing loudly (a `FAIL`
   line, not silent corruption) instead of trusting every caller's buffer
   was big enough. A reminder that "the test suite has passed for five
   phases in a row" and "the test suite is memory-safe" are not the same
   claim, and this project's own tools/ directory is not exempt from the
   scrutiny its production code gets.

Verified:
- `make h2-fuzz`: all 6 targets, 200,000 iterations each, re-run across 6
  independent seeds (over 18 million total operations) -- all pass after
  the fix, none did before it.
- `make h2-fuzz-san` / `make h2-test-san`: GCC ASan+UBSan, multiple seeds
  -- clean.
- The complete existing host suite and the full 19-script QEMU regression
  sweep, re-verified against the `hpack_table_get()` fix specifically
  (a strict rejection of an out-of-range index no legitimate server
  response would ever produce) -- unaffected.

## Step 17.5.2 — HTTP/2 hardening: stress & interoperability

17.5.1 proved fuzzing pays for itself by finding a real bug within
minutes. This phase asks a different question: does everything already
built hold up not against random bytes, but against genuinely large
scale, genuinely long-lived state, and genuinely independent
implementations nobody on this project wrote? Five sub-items, each with
its own QEMU test, closing out the "17.5 Hardening" series.

**Item 1 -- large responses (1/5/20 MB).** The biggest response any test
had ever attempted was 200 KB (17.4.3's own flow-control test). Reaching
"hundreds of typed path arguments" or "one huge fetch" ran straight into a
shell limit that had nothing to do with HTTP/2 at all: `user/sh.c`'s
`tokenize()` caps a typed command at `ARG_MAX` (16) tokens, so "one path
argument per fetch" cannot scale past a handful of requests regardless of
`httpsget`'s own `MAX_PATHS`. `httpsget.c` gains `--repeat N`: one short
typed command loops `fetch_one()` N times over the same path, reusing
whatever connection the first iteration opened exactly the way repeating
that path N times in `argv` already would -- no new fetch logic, just a
way to reach a large N without a large `argv`.

**Item 2 -- long-lived connections.** `tools/h2_longlived_qemu.py`: 300
sequential requests over ONE reused connection (`--repeat 300`), each
response inserting one never-repeated dynamic-table entry so decoding
request *N* only succeeds if every insertion and eviction before it (the
dynamic table holds roughly 95 such entries before RFC 7541 §4.4 eviction
starts) was tracked correctly -- and each response's connection-level
window draining a little, crossing the replenishment threshold repeatedly
across the run (17.4.3's own test only ever climbed to that threshold
once, in one huge stream). All 18 checks pass: stream IDs reach 599,
every response decodes correctly, multiple WINDOW_UPDATE cycles observed.

**Item 3 -- HPACK stress.** `tools/h2_hpack_stress_qemu.py`, five
scenarios over one connection: a ~3000-byte single custom header value
(comfortably under `H2_HPACK_SCRATCH_MAX`'s 4096 bytes, but far past
anything tested before); 40 `Set-Cookie` headers in one response; three
Dynamic Table Size Update instructions back to back in one header block
(RFC 7541 §6.3 explicitly permits this: shrink to 0, evicting everything,
grow to 100, grow back to 4096, then prove the table still works with a
literal-incremental insert); and 40 literal-incremental fields in one
block whose cumulative size (~4120 bytes) exceeds the dynamic table's own
4096-byte arena, forcing eviction *within a single decode call* rather
than gradually across many requests, a dimension item 2's own test
doesn't cover. Designing the cookie scenario is what surfaced this
phase's second real bug (below).

**Item 4 -- negative tests.** `tools/h2_goaway_qemu.py`: GOAWAY sent
instead of the server's own SETTINGS (exercising `h2_handshake()`'s own
check) and GOAWAY sent mid-response, after HEADERS plus one deliberately
incomplete DATA frame with no END_STREAM (exercising `h2_fetch()`'s own
check). Both already printed a diagnostic and returned -1 per code
inspection and per 17.5.1's own fuzzing of the decode functions in
isolation -- neither simulates a live, multi-frame protocol *exchange*
the way a real, adversarial server does, so this test verifies it against
one. Both scenarios: Aurora exits promptly (proven by the shell's own
`[exit N]` line appearing well inside the wait budget, not just "QEMU's
timeout eventually fired") with a nonzero status and no crash.

**Item 5 -- real-server interoperability.** `tools/h2_nginx_interop_qemu.py`:
a real, unmodified `nginx` (Ubuntu's stock package, `apt-get install
nginx`, built with `--with-http_v2_module`; launched from its own
throwaway config in a tempdir, never touching the system's default site
or logs, killed on exit) -- the first peer in this entire project that
isn't a hand-rolled Python script controlling both ends of the wire.
Fetches a small text file and a 300000-byte binary file over one reused
connection. Apache/Caddy/Envoy/nghttp2 were out of scope for this pass
(none installs via a plain `apt-get install` in this environment; each
would need a PPA, snap, or a from-source build) -- nginx alone still
answers the question this item exists for.

**Three real bugs found, none of them hypothetical:**

1. **A genuine TCP protocol bug** (`net/tcp.c`'s `tcp_input()`): the
   ACK-send condition was only `if (c->tcb.rcv_nxt != before)` -- true
   exclusively when a segment actually advanced the receive sequence. A
   duplicate segment (already-received data retransmitted because
   Aurora's own earlier ack for it never went out), a genuinely
   out-of-order segment, or an in-order segment that didn't fit the
   current window all got ZERO acknowledgment. RFC 793/5681 require an
   immediate current ACK in every one of those cases -- without it, a
   real sender has no way to learn "you already have this" or "here is my
   real window" short of its own retransmit timer, and the connection can
   stall indefinitely from the receiver's side. First surfaced as a dead
   stall at ~340 KB into a large-response test -- past 200 KB, the
   largest size any prior phase had ever attempted, and past whatever
   threshold this exact interaction needed to actually manifest. Captured
   directly: a real kernel TCP sender (Linux, via a Python test server,
   not a hand-rolled test peer) retransmitting an already-received
   segment several times in a row with Aurora completely silent in
   response. Fixed by sending a current ACK for any data- or FIN-bearing
   segment, not only ones that advance `rcv_nxt`. A related, independent
   defect in the same area was fixed alongside it: `tcp_tick()` kept
   blindly retransmitting a still-`pending` segment on a connection
   that had already gone `TCP_CLOSED` (a RST doesn't itself clear
   `rtx.pending`) -- harmless before, but pointless, and it kept spamming
   a peer that had long since forgotten the connection existed. (An
   initial hypothesis for a *different*, later symptom -- a data race on
   `tcp_xmit()`'s shared static segment buffer, "fixed" with a `cli`/`sti`
   critical section -- was tried, re-tested, found not to change the
   outcome at all, and reverted; see bug 3 below for what the real cause
   turned out to be. Recorded here as a reminder that a plausible-sounding
   fix is not a verified one until the test that exposed the bug actually
   passes because of it.)
2. **Cookies never actually flowed both directions over HTTP/2.**
   `http2/headers.c`'s `h2_build_headers()` had no cookie parameter at
   all. A session cookie learned from an h2 response's own `Set-Cookie`
   was stored correctly the entire time -- via the exact same
   `resp_feed()`/`cookie_jar_set()` tail HTTP/1.1 responses already use,
   shared code, nothing h2-specific to get wrong there -- but was simply
   never sent back on a *later* h2 request, even one reusing the very
   connection that set it. Cookie persistence silently worked in only one
   direction over h2, since Phase 17.3 first made a real h2 GET possible,
   and nothing before this phase ever tested a second h2 request that
   depended on a cookie the first one set. Found while designing this
   phase's own "many cookies" HPACK-stress scenario, not by code
   inspection. Fixed: `http2/hpack.h` gains `HPACK_IDX_COOKIE` (static
   table index 32, RFC 7541 Appendix A); `h2_build_headers()` takes an
   optional cookie value, encoded exactly like `user-agent` already is --
   a literal with an indexed name, never dynamically indexed, matching
   this encoder's existing rule of never indexing a value that varies per
   request rather than describing the connection/page itself;
   `h2_fetch()` builds it from the cookie jar via
   `cookie_jar_build_header()`, identically to `build_request()`'s own
   HTTP/1.1 Cookie header, and now takes `now` for the jar's expiry
   checks. Verified precisely, not just "a cookie arrived": the HPACK-
   stress test's `/echo` step sets 40 distinct cookies from one response
   (`COOKIE_JAR_N`, 32, forcing real LRU eviction of the 8 set first),
   then decodes the *real* third request's own HEADERS frame and confirms
   its Cookie header contains exactly the 32 survivors and none of the 8
   evicted -- both the fix and the jar's eviction math proven against the
   real wire encoding in one check.
3. **A test-harness bug that looked like a protocol bug until measured.**
   After fixing bug 1, a *different* failure appeared further into
   large-response testing: an outbound WINDOW_UPDATE write failing
   outright, well past where the original stall used to happen. This one
   was in the test's OWN Python server, not in Aurora: `tls.sendall()`
   returning only means the OS queued the bytes into its own send
   buffer, not that Aurora received them. Direct measurement during this
   same investigation put Aurora's real throughput at roughly 1.2-1.5
   KB/s -- Aurora's own from-scratch ChaCha20-Poly1305 record decryption
   running on an emulated i686 CPU is the bottleneck, not the
   (effectively localhost) QEMU network -- meaning Aurora is still slowly
   receiving and acknowledging a large response for a long time after
   `sendall()` already returned. The test's server closed its socket
   immediately afterward anyway, stranding that still-in-flight data
   against an already-torn-down socket; any further packet Aurora sent
   (an entirely routine WINDOW_UPDATE ack) got an immediate "no such
   connection" RST from the peer OS, which then made Aurora's own next
   write fail outright -- from Aurora's side, indistinguishable from a
   real bug. Diagnosed by direct measurement (a standalone throughput
   probe, and a background investigation agent that traced the exact TCP
   sequence numbers in the RST) only after an *initial* wrong hypothesis
   (bug 1's own `cli`/`sti` attempt, above) was tried, re-tested, and
   shown NOT to change the outcome. Fixed in the test's own server: keep
   draining whatever Aurora sends back -- parsed as real H2 frames, not
   raw discarded bytes, a second, smaller bug caught in the fix's own
   first draft when it silently stopped counting WINDOW_UPDATE cycles for
   any single-fetch (`--repeat 1`) test -- until Aurora goes idle, before
   closing. Given the ~1.2-1.5 KB/s ceiling this measurement established,
   5 MB and 20 MB were tested with a single fetch each rather than
   `--repeat 2`'s double-fetch (which 1 MB alone still uses, completing
   in ~40 minutes; 5 MB and 20 MB at double-fetch would have cost roughly
   2.5 and 10+ hours respectively) for a property -- no leak/stale-state
   drift across repeated fetches on one connection -- already proven
   twice over: once at 1 MB here, and independently, at full
   connection-reuse scale, by item 2's own 300-request run.

Verified:
- `tools/h2_large_qemu.py`: 1 MB (`--repeat 2`), 5 MB, and 20 MB, all ALL
  PASS -- exact byte counts, correct stream IDs, multiple WINDOW_UPDATE
  cycles at every size, no leak/drift between the two 1 MB fetches.
- `tools/h2_longlived_qemu.py`: 300 sequential requests, ALL PASS.
- `tools/h2_hpack_stress_qemu.py`: all five scenarios (big header, many
  cookies + real cookie-over-h2 round-trip, triple Dynamic Table Size
  Update, intra-block mass eviction), ALL PASS.
- `tools/h2_goaway_qemu.py`: both scenarios (handshake-time and
  mid-response GOAWAY), ALL PASS.
- `tools/h2_nginx_interop_qemu.py`: real nginx, ALL PASS.
- Full existing host suite, `make h2-fuzz`, and a broad QEMU regression
  sweep -- explicitly including `keepalive_qemu.py`, since the
  `net/tcp.c` fix touches code shared by every TCP connection Aurora
  makes, HTTP/1.1 included, not just h2 -- all re-verified unaffected.

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

## Step 18.5 — Performance Characterization: measurement before optimization

Before touching TLS/HTTP2 performance, 18.5 asked what's actually slow,
rather than assuming it and optimizing the wrong layer. 18.5.2 added
kernel-wide counters (`struct kernel_prof`, `SYS_PROFSTAT`): scheduler
switches, wait-queue blocks, `tcp_input`/`tcp_tick` calls and time,
`memcpy`, FAT read/write. 18.5.3 added the userspace equivalent
(`user/uprof.h`, `httpsget --profile`): AEAD seal/open, HPACK
encode/decode, HTTP/2 frame processing, each as calls/time/bytes.

**18.5.3.1 — the characterization sweep.** `tools/perf_characterize.py`
drives `httpsget --profile` against real H2/HTTP-1.1 servers (reusing
`h2_large_qemu.py`/`keepalive_qemu.py`/`tls_resume_qemu.py` rather than
building a third set of test servers) across response size (1 KB → 5 MB),
protocol (HTTP/1.1 vs HTTP/2), connection setup (cold handshake vs TLS
resumption), and reuse (one request vs fifty over one connection) — ten
scenarios, one merged `tools/perf_characterize_results.json`. The
standing hypothesis going in was that `aead_open` (Aurora's from-scratch
ChaCha20-Poly1305, running on an emulated i686 core) would dominate wall
time at scale. Measured: at 5 MB, `aead_open` is 291 ms of a 1114.4 s
transfer — 0.026%. Every profiled subsystem combined (AEAD, HPACK, frame
processing, `tcp_input`, `tcp_tick`) is 1.79 s — 0.16%. The hypothesis is
false; crypto and framing are not the bottleneck at any size tested, and
an AEAD speedup (SIMD, batching) was explicitly ruled out as the next
step on this evidence.

Two bugs were found and fixed in the *test harness* during this sweep
(neither is an Aurora bug): typing `"httpsget ... ; profstat"` as one
serial-console line doesn't chain two commands — Aurora's shell has no
`;` separator, so `; profstat` became two more argv tokens fed straight
to `httpsget`, which for a bodyless GET treats every trailing non-path
token as an override of `now` (the TLS certificate-validation clock),
corrupting it to ~0 and producing a perfectly reproducible "leaf not yet
valid" failure with nothing to do with clocks or certs. Fixed by typing
two genuinely separate lines. Separately, a daemon accept-thread in the
test servers doesn't reliably release port 443 when closed from another
thread within the same process (a POSIX `close()`-vs-blocking-`accept()`
race) — fixed by running every server-backed scenario as its own OS
process, merging results by scenario name afterward.

**18.5.4 — where the profiled time doesn't reach.** Two numbers from
18.5.3.1 still needed an explanation: roughly 150–175 scheduler
`wait_blocks` per 16 KB HTTP/2 DATA frame, and `tcp_tick_calls` running
~140,000–150,000 for HTTP/2 scenarios against 9 for HTTP/1.1 on an
identical 10 KB body. New counters (`tcp_read_calls`/`tcp_read_iters`/
`tcp_read_bytes`/`tcp_wait_us` in `net/tcpsock.c`'s `tsk_read()`, plus a
call-site counter for each of `net/tcpsock.c`'s other three `net_poll()`
sites — connect, write, close) answered both directly instead of by
inspection:

- The `wait_blocks` count is not small reads: at 100 KB, 22 `read()`
  calls return ~4.7 KB on average (above one TCP segment), and
  `tcp_wait_us`/`wait_blocks` ≈ 19.9 ms confirms `wait_event_timeout()`
  is genuinely sleeping its nominal ~20 ms each time, not spinning. The
  count is simply (seconds needed to fill one frame at this
  environment's actual delivery rate) ÷ (20 ms poll interval) — a
  consequence of transfer speed, not a defect in the wait loop.
- `tcp_tick_calls` traced entirely to `tcp_close_iters`: 144,817 (HTTP/2)
  vs. 1 (HTTP/1.1). `tcpsock_close()`'s teardown-wait loop had **no
  yield at all** — an unconditional busy-spin for its full 1500 ms
  budget whenever the peer hadn't already closed first. The HTTP/1.1
  test server closes immediately (a passive close completes in one
  check); the HTTP/2 test server deliberately keeps the connection open
  (its own comment: closing early would strand Aurora's still-arriving
  WINDOW_UPDATEs against this environment's slow crypto), forcing
  Aurora into an *active* close, which must sit in `TCP_TIME_WAIT`
  (`TCP_TIME_WAIT_MS` = 1000 ms fixed) — a dwell the 1500 ms budget
  can't reliably absorb without spinning through nearly all of it.
  Confirmed protocol-agnostic (a generic close-path defect, not
  anything HTTP/2-specific) and confirmed per-*connection*, not
  per-request: `reuse:50x1KB`'s `tcp_close_iters` (135,705) is the same
  order as `reuse:1x1KB`'s (141,119) despite fifty requests instead of
  one. Fixed: `tcpsock_close()` now parks on the connection's own wait
  queue between polls, exactly like `tsk_read()`/`tsk_write()` already
  do — `tcp_input()` already wakes it promptly on anything relevant,
  and `tcp_tick()` still flips `TIME_WAIT` to `CLOSED` on schedule, so
  the loop's exit condition is unchanged, only how it waits. Re-verified
  on four scenarios (`protocol_h2`, `protocol_h1`, `size_1k`,
  `reuse_50x`): `tcp_close_iters` for HTTP/2(10 KB) dropped from 144,817
  to 52 (≈ the `TIME_WAIT` floor at a 20 ms poll interval) with
  identical `200 OK` results and `wall_us` within run-to-run noise. The
  spin ran *after* the response was already fully received (outside
  `httpsget`'s own measured `wall_us`), so it never explained
  18.5.3.1's request-latency numbers — those stand unchanged — but it
  was real, wasted, ~1.5 s-of-100%-CPU per HTTP/2-style close.

**18.5.5 — ruling out the driver and the receive window.** Two follow-up
questions remained: does the ~20 ms poll interval actually pace data
delivery (a virtio-net/IRQ/scheduler-tick question), and does the
16 KB receive ring (`RX_RING_CAP`) starve against `httpsget`'s ~6.4 KB
read buffer (a flow-control question)? Both answered by measurement,
both closed as *not* the cause:

- `profstat` now also prints the driver's own pre-existing
  `struct net_stats` (`rx_irqs`, `rx_packets`, ...; it already existed
  for the Settings app's network panel, just was never surfaced next to
  the kernel counters). `rx_irqs` stays within ~1.2–1.5× of `rx_packets`
  across every scenario measured — interrupts track real packet
  arrivals, not a source of spurious wakeups. But `tcp_tick_calls`
  (`net_poll()` calls) runs 2.8×–9.2× higher than `rx_packets`, and
  that ratio *grows* with transfer size: most polls find nothing,
  because packets physically arrive on the wire far slower than the
  20 ms poll interval (measured: ~82–87 ms/packet at 10 KB, ~188 ms/
  packet at 100 KB) — the poll loop is already faster than the data,
  not the other way around.
- A receive-window trace (`wnd_zero_events`/`wnd_closed_us` in
  `net/tcp.c`, timestamped from the moment `rcv_wnd` hits exactly 0 to
  the moment `tcp_recv()`'s existing reopening branch fires) tested the
  hypothesis directly. Result at 100 KB: the window closed twice in the
  entire transfer, for 273 *microseconds* total — 0.0013% of a 21.5 s
  wall time. HTTP/1.1 and HTTP/2 at 10 KB never closed the window at
  all. `tcp_recv()`'s reopening ACK is exactly as synchronous as the
  code reads; there is no hidden delay there.

**Where this leaves 18.5.** Every layer inside Aurora's own client-side
path has now been measured, not assumed: AEAD/TLS, HPACK/HTTP-2 framing,
userspace `read()` sizing, the wait-queue mechanism, the busy-spin found
in `close()` (fixed; confirmed not a throughput factor), the IRQ/driver
path, and receive-window management are all cleared as explanations for
this environment's ~4.6–5 KB/s effective bulk-transfer rate. What
remains sits outside Aurora entirely — QEMU's own `slirp` user-mode
network emulation (well known for elevated latency, not built for
throughput measurement) or the Python test servers' own send-side
pacing (Nagle interacting with per-frame `sendall()` calls, TLS record
boundaries) — neither reachable from inside the guest. The natural next
step is an external control experiment (the same Python server, same
QEMU/slirp path, a Linux guest's `curl` in Aurora's place) to attribute
the remaining latency to the environment rather than the OS; this is
tracked as a standalone "Throughput under QEMU/slirp" investigation and
does not block further Aurora development. 18.5 is closed on that basis:
its goal was a profile and a localization, not a throughput fix, and
both are now as complete as they can be from inside the guest.

## Step 18.5.6 — kernel stack guard pages

A new initiative, not a continuation of 18.5's TCP investigation: with the
network/HTTP arc mature, the next highest-value work shifts to platform
quality rather than another protocol -- starting with a defect class this
project had already hit once for real. 17.5.2/18.5.2 uncovered a genuine
kernel stack overflow in `fs/fat32.c` (`fat_write_impl()` calling
`fat_update_dirent()` with both functions' own 4 KB `cbuf` locals live on
the stack simultaneously, exactly filling `STACK_SIZE`), fixed at the time
by making the buffers `static` -- a point fix for one call path, with the
commit itself noting *"there is no guard page below a kernel stack here, so
the overflow didn't fault immediately -- it silently overwrote whatever
kmalloc'd memory happened to sit next to it"*. This phase closes that gap
generally, for every thread, not just that one call path.

**The allocator.** `kernel/scheduler.c`'s `alloc_thread()` (shared by
`thread_create_kernel()`, `thread_create_user()`, and
`thread_create_trampoline()` -- every thread this kernel ever creates)
used to get its `STACK_SIZE` (8 KiB) stack from a plain `kmalloc()`, an
ordinary heap object with no guarantee of page alignment, sitting
back-to-back with other heap allocations. It now gets a dedicated 3-page
slot from a small new virtual arena (`KSTACK_AREA_BASE = 0xF0000000`,
64 slots, `kstack_slot_alloc()`/`_free()` tracking which are in use): one
page mapped via `vmm_map_page()`/`pmm_alloc_frame()`, left **unmapped** as
a guard, directly below the `STACK_SIZE`/`PAGE_SIZE` (= 2) pages that are
the actual stack. `thread_free()` unmaps and returns those frames and the
slot on thread exit. The boot thread (`main_thread`/`main_kstack[4096]`,
a singleton static array predating `alloc_thread()`) is a known,
documented exception -- not guarded, matching its pre-existing
not-page-aligned, half-size special case.

Found the hard way, not designed for up front: the very first `exec` after
boot silently hung forever once this landed. `vmm_create_address_space()`
clones the shared high-memory PDEs *by value*, read through the recursive
self-map of whichever page directory happens to be active at that moment
-- not copied from one fixed canonical "the kernel's" directory. A page
table that doesn't exist yet in the currently active directory when a new
process is created never propagates to it. `lib/kheap.c`'s `kheap_init()`
already pre-creates its own region's page tables via `vmm_ensure_table()`
specifically to sidestep this, with a comment saying exactly why; the new
kstack arena needed the identical treatment (one `vmm_ensure_table()` call
in `scheduler_init()`, before any thread — and so any process — exists),
added once the hang made the dependency obvious.

**The double-fault problem.** A guard page only matters if hitting it
produces a usable diagnostic instead of silent wreckage further down the
line. The naive version doesn't: a same-privilege (ring0->ring0) page
fault delivers its exception frame onto the *current* stack, unchanged --
if that stack is itself the thing that's unmapped, the CPU's own delivery
attempt re-faults at the *exact same address* the original instruction
just failed to write (a faulting `push` doesn't move ESP, so the exception
frame's first push targets that identical slot), escalating page-fault
during page-fault to a double fault, which re-faults the same way trying
to deliver *itself*, guaranteeing a triple fault -- a bare VM reset with
no OS-level message at all. Confirmed directly, not assumed: a first cut
of `SYS_DEBUG_KSTACK_OVERFLOW`'s test (`kstacktest.elf`, a tight recursion
eating 512+ bytes per frame) reliably triple-faulted with zero output;
QEMU's own `-d int,cpu_reset` trace showed the exact PF -> PF(as #DF) ->
#DF(as triple fault) cascade, CR2 identical across all three. Fixed with
the standard i386 protected-mode technique for exactly this problem:
vector 8 (#DF) is now a **task gate** (`arch/i386/gdt.c`'s `df_tss`, its
own small dedicated stack, CR3 patched in once `paging_init()` has run --
`gdt_install()` itself runs too early for CR3 to be meaningful), not an
ordinary interrupt gate. A hardware task switch loads an entirely fresh
register set (including ESP/SS) *before* executing a single instruction of
the handler, so double-fault delivery needs no stack space from the
broken context at all. `arch/i386/isr.c`'s `df_handler_entry()` reads the
outgoing task's last `eip`/`esp` from the main TSS (the CPU saves them
there as part of the switch, since this kernel has never done a hardware
task switch before and TR still references it) and prints a specific
"DOUBLE FAULT -- almost certainly a kernel stack overflow" message before
halting. Vector 14's own handler is unchanged and still handles the
(less severe, less common) case directly: reading CR2 and printing
"KERNEL STACK OVERFLOW" for a guard-page hit that doesn't happen to land
exactly on ESP itself.

**Verification.** `tools/guard_page_qemu.py` is a permanent QEMU
acceptance test, not a one-off: types `kstktest`, accepts either
diagnostic as a pass (which one fires is a property of exactly how the
overflow lands, not a choice), and fails on a hang, a silent return, or
the generic exception fallthrough. Re-verified the actual original bug
scenario directly: `save /disk/TEST.TXT <text>` followed by process exit
(the exact `fat_write_impl`/`fat_update_dirent` shape that started this)
completes cleanly. Full clean rebuild plus a regression sweep (every host
test: crypto/tls/x509/url/crc32/inflate/gzip/h2; `tools/prof_qemu.py`;
`tools/dns_cache_qemu.py`; `tools/tls_resume_qemu.py`) all still pass --
this touches every thread this kernel creates, so breadth mattered more
than depth here.

## Step 19.2 — stack canaries: kernel and userspace

**What.** Both build trees now compile with `-fstack-protector-strong`
(kernel `CFLAGS` and userspace `UCFLAGS` both previously pinned the
protector OFF): every function with a local array or address-taken local
gets a hidden canary word between its locals and its saved ebp/return
address, re-checked on return. A mismatch means the frame was overwritten;
the check fires BEFORE the corrupted return address can be used. This is
the layer 19.1's guard page architecturally cannot provide: the guard page
catches an overflow that runs off the END of the stack's mapped pages,
but says nothing about an overflow that stays inside them — a 64-byte
buffer overrun by 64 bytes corrupts its own frame's return address and
never comes near the guard page. 17.5.1 already found exactly this bug
class for real (tools/h2_test.c's `check_hex()` overflow, silent through
every prior run until ASan caught it on the host); canaries are the
in-guest, always-on version of that detection.

**Freestanding runtime, kernel side** (arch/i386/stack_protector.c/.h).
clang targeting bare `i686-elf` emits references to a global
`__stack_chk_guard` and calls `__stack_chk_fail()` on mismatch; nothing
provides those in a `-nostdlib` build, so the kernel now does. The fail
handler prints `*** KERNEL STACK SMASHING DETECTED` with the failing
function's address (`__builtin_return_address(0)` — the one word the
corruption is guaranteed NOT to have reached, since the call that pushed
it happens after the check compares) and halts; a frame whose canary is
gone cannot be safely returned through, so halting is the only honest
option in ring 0. The guard is reseeded once at boot from the TSC
(`stack_protector_init()`, the first statement in `kernel_main()`) — no
RNG dependency, per-boot unpredictability. The one reseed hazard is
documented in the init contract: any function with a frame alive ACROSS
the reseed would compare its old copy against the new value and die
falsely; at that point in boot the only such frame is `kernel_main()`
itself, which never returns, so its check never runs.

**Per-thread canary ABI** (kernel/scheduler.c). A single fixed guard
would mean every thread checks against the same value forever. Instead
`thread_t` carries `stack_canary = stack_canary_for(tid, stack_base)` — a
deterministic hash (Knuth multiplicative mix + xorshift avalanche) of the
boot seed, the tid and the stack base: no rand(), reproducible within a
boot, different across boots and across threads — and `do_switch()` (and
`thread_zombie_and_yield()`'s inline switch) writes the INCOMING thread's
value into the global `__stack_chk_guard` on every context switch. That
is coherent because a frame's canary is pushed and checked only while its
own thread executes, and the global holds that thread's value for the
whole window; the boot thread's canary is set to the already-reseeded
global (its frames were pushed against it), and IRQ handler frames
complete within the thread they interrupted. This is the same trick
Linux's !SMP x86 stack protector uses, for the same reason.

**Stack-END canary** (second, independent layer). alloc_thread() writes
the thread's canary value into the lowest word of its stack — directly
above 19.1's guard page — and it is checked at exactly three cheap
chokepoints, never in a hot loop: context switch (`do_switch()`), syscall
exit (`syscall_handler()`'s tail, one load+compare per syscall), and
`thread_free()`. It catches the case both other layers miss: a write that
reached the very bottom of the mapped stack without crossing into the
guard page and without being a compiler-visible frame overflow (e.g. a
large memset through a pointer, or an alloca-style skip landing short of
the boundary).

**Stack high-water mark** (profiling hook, same commit). `do_switch()`
also samples the OUTGOING thread's live ESP (the in-register value, not
the stale `thread->esp`, which `switch_task()` only updates as it leaves)
and records the deepest `kstack_top - esp` seen into the new
`kernel_prof.kstack_max_used` counter, surfaced by `profstat` and parsed
by tools/perf_characterize.py. Switch points are where stacks are deepest
in practice (every blocking path ends in one), but a deep chain that
never blocks or preempts at its deepest frame is not sampled — the field
is documented as a lower bound, not an exact peak. (A measured value from
a real boot is recorded at the end of this step, below.)

**Userspace.** UCFLAGS gets the same flag; the runtime lives in
user/libc/ssp.c (linked into every program via LIBC_OBJ, including the
whole freestanding TLS/HTTP/2 stack built from TLS_U_SRC — precisely the
code that parses hostile network input). One honest difference, stated in
the file: the userspace guard is a FIXED constant, because crt0 jumps
straight to main with no libc init hook and Aurora has no getrandom()
yet — it reliably catches accidental corruption (the common case) but a
targeted exploit that reads the binary knows the value; per-process
entropy belongs to the future ASLR phase. A smashed process prints
`*** stack smashing detected` and `_exit(134)`s (128+SIGABRT by
convention) — the process dies, the OS does not.

**Acceptance test** (SYS_DEBUG_STACK_SMASH=49, user/canarytest.c,
tools/canary_qemu.py — permanent, like guard_page_qemu.py). Phase 1
smashes a userspace buffer in a fork()ed child: the child aborts with
status 134, the parent (and the OS) keep running. Phase 2 calls the new
syscall, which overruns a 64-byte kernel frame buffer by 64 bytes through
a volatile pointer with a volatile length (so -O2 can neither prove UB
nor delete the write): far enough to clobber the compiler canary, and
deliberately nowhere near the guard page, so the resulting halt is
attributable to THIS phase's mechanism alone. The test also asserts the
halt text is the canary diagnostic and NOT "KERNEL STACK OVERFLOW" /
"DOUBLE FAULT" / a generic exception — a regression in either 19.1 or
19.2 shows up in exactly one of the two acceptance tests, not smeared
across both.

**What each layer now catches** (the full kernel-stack model):

| corruption shape                                  | caught by       |
|---------------------------------------------------|-----------------|
| overflow past the end of the mapped stack          | guard page (19.1), first OOB write |
| overflow with ESP itself left invalid              | task-gate #DF handler (19.1) |
| in-frame overrun reaching the return address       | compiler canary (19.2), at return |
| write reaching the stack's last word, not crossing | stack-end canary (19.2), at switch/syscall-exit/free |
| creeping depth growth (no corruption yet)          | kstack_max_used watermark (19.2), observable in profstat |

**The watermark's first read-back found a real bug in itself** — worth
recording as method, not just result. The first `profstat` after the
feature landed reported `kstack_max_used=4293662012` (~4.29 GB "used" of
an 8 KiB stack): `kstack_top - esp` had underflowed, because the BOOT
thread executes on boot.S's own 16 KiB `stack_top` stack while its
`thread_t.kstack_top` points at the separate (and for execution purposes
unused) `main_kstack[]` array — an address mismatch that had sat harmless
in the code since the scheduler was written, exposed the moment something
actually did arithmetic with it. Fix: the watermark samples guard-paged
threads only (`prev->kstack != NULL`), same singleton boot-thread carve-
out as the guard page and the end canary. Measured after the fix: an
idle boot peaks at 156 bytes at switch points; a fork/exec + FAT
read/write workload (`cat` + `save` + `profstat`) peaks at 280 bytes.
Blocking paths, in other words, sit nowhere near the 8 KiB limit — the
historical overflow (fs/fat32.c) came from a deep NON-blocking chain,
which is exactly the kind this counter's lower-bound caveat says it
cannot see, so the small number is reassuring about steady-state depth
while proving nothing about worst-case call chains. Both layers of
canaries exist precisely for what the counter can't see.

Verified: tools/canary_qemu.py ALL PASS (both phases, correct halt text);
tools/guard_page_qemu.py still ALL PASS (the two debug halts stay
distinct); full host suite (all 24 targets: crypto/tls/tls-trace/crc32/
inflate/gzip/h2/h2-san/h2-fuzz-san/x509/rsa/p256/p384/ecdsa/ecdsa384/url/
cookiejar/base64/ca-roots/dns-cache/dhcp/rxring/tcp-reassembly/tcp-window)
ALL PASS; QEMU regression under real scheduler load — prof_qemu,
tcp_sendwin_qemu, keepalive_qemu, securehttps_qemu, h2_reuse_qemu,
h2_large_qemu (1/5/20 MB transfers, thousands of context switches with
the per-thread guard swap active) — ALL PASS. The per-thread swap
survived every fork/exec/block/IRQ-preemption path in the suite with
zero false positives.
