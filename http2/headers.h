/* HTTP/2 HEADERS frame (RFC 7540 §6.2) — Phase 17.1.3, extended 17.4.1.
 *
 * Builds a real HTTP/2 request: the four required pseudo-headers (:method,
 * :scheme, :authority, :path -- RFC 7540 §8.1.2.3), a user-agent, and --
 * when the request carries a body (Phase 17.4.1: POST/PUT/PATCH, matching
 * the userspace client's own --method support, 16.5) -- Content-Type and
 * Content-Length, all HPACK-compressed using ONLY the static table
 * (hpack.c) -- no Huffman, no dynamic table (this client's own encoder
 * deliberately never uses either; see hpack.h's header comment). */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "frame.h"

/* Build a HEADERS frame into `out`: :method (`method`/`method_len`),
 * :scheme (always "https" -- this client only ever reaches h2 over TLS, so
 * there is nothing to parameterize), :authority (`authority`/
 * `authority_len` -- the request's Host-equivalent), :path (`path`/
 * `path_len`), and user-agent (`user_agent`/`user_agent_len`; pass
 * `user_agent = NULL` to omit it).
 *
 * `body_len` is the request body's length in bytes (0 for a bodyless
 * request -- GET/HEAD/OPTIONS/DELETE). When nonzero, `content_type`/
 * `content_type_len` (required in that case) are sent as a literal
 * Content-Type header, and a Content-Length header carrying `body_len`
 * itself (formatted as decimal ASCII) is added automatically -- the
 * caller never computes that text itself, the same way build_request()'s
 * own HTTP/1.1 Content-Length is always derived from the real body length,
 * not passed in separately and trusted to match.
 *
 * Always sets END_HEADERS (the whole header block fits in one frame -- no
 * CONTINUATION needed for a request this small). Sets END_STREAM only when
 * `body_len` is 0 -- when it's nonzero, the caller is responsible for
 * following this frame with one or more DATA frames (h2_data_build(),
 * http2/data.h) carrying exactly `body_len` bytes, the last one with
 * END_STREAM set.
 *
 * Returns the total frame length (header + payload) or -1 on a capacity
 * error. */
int h2_build_headers(uint8_t *out, size_t cap, uint32_t stream_id,
                     const char *method, size_t method_len,
                     const char *authority, size_t authority_len,
                     const char *path, size_t path_len,
                     const char *user_agent, size_t user_agent_len,
                     const char *content_type, size_t content_type_len,
                     size_t body_len);
