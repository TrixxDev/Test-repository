/* HTTP/2 HEADERS frame (RFC 7540 §6.2) — Phase 17.1.3.
 *
 * Builds a minimal, real HTTP/2 request: the four required pseudo-headers
 * (:method, :scheme, :authority, :path -- RFC 7540 §8.1.2.3) plus a
 * user-agent, HPACK-compressed using ONLY the static table (hpack.c) --
 * no Huffman, no dynamic table (both are a later phase). This is
 * deliberately encode-only: nothing decodes a HEADERS frame the server
 * sends back yet (that needs Huffman and/or the dynamic table, since a
 * real server's response headers routinely use both), so h2_handshake()'s
 * caller still can't complete a real fetch after this -- it can now send
 * a genuine request, which is the actual point of this phase. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "frame.h"

/* Build a HEADERS frame into `out`: :method (`method`/`method_len`),
 * :scheme (always "https" -- this client only ever reaches h2 over TLS, so
 * there is nothing to parameterize), :authority (`authority`/
 * `authority_len` -- the request's Host-equivalent), :path (`path`/
 * `path_len`), and user-agent (`user_agent`/`user_agent_len`; pass
 * `user_agent = NULL` to omit it). Always sets END_HEADERS (the whole
 * header block fits in one frame -- no CONTINUATION needed for a request
 * this small) and END_STREAM (this client doesn't send a request body over
 * h2 yet). Returns the total frame length (header + payload) or -1 on a
 * capacity error. */
int h2_build_headers(uint8_t *out, size_t cap, uint32_t stream_id,
                     const char *method, size_t method_len,
                     const char *authority, size_t authority_len,
                     const char *path, size_t path_len,
                     const char *user_agent, size_t user_agent_len);
