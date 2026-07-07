/* HTTP/2 DATA frame (RFC 7540 §6.1) — Phase 17.1.2.
 *
 * A DATA frame carries part of a request/response body on an open stream.
 * No stream is ever open yet (that's a later phase -- HEADERS doesn't exist
 * yet either), so nothing in this client acts on a DATA frame's content
 * today; this is the payload-shape half of "recognize every frame type
 * correctly," parallel to settings.c's role for SETTINGS. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "frame.h"

/* Parse a DATA frame's payload (the bytes after the 9-byte frame header,
 * NOT including it). If H2_FLAG_PADDED is set in `flags`, the payload
 * begins with a 1-byte Pad Length field, followed by the actual data,
 * followed by that many bytes of padding (RFC 7540 §6.1 says padding
 * SHOULD be zero, but doesn't require a receiver to check its content, and
 * neither does this). Sets *data and *data_len to the actual data bytes -- a
 * slice of `payload`, no copy. Returns 0, or -1 if `payload_len` is too
 * short to even hold its own declared Pad Length, or the declared padding
 * is >= the whole payload (RFC 7540 §6.1: "If the length of the padding is
 * the length of the frame payload or greater, the recipient MUST treat
 * this as a connection error"). */
int h2_data_parse(const uint8_t *payload, size_t payload_len, uint8_t flags,
                  const uint8_t **data, size_t *data_len);

/* Build a DATA frame (9-byte header + payload) into `out`. Never adds
 * padding -- Aurora only needs to tolerate receiving it, not send it.
 * `end_stream` sets H2_FLAG_END_STREAM. Returns the total frame length
 * (header + payload) or -1 on a capacity error. */
int h2_data_build(uint8_t *out, size_t cap, uint32_t stream_id,
                  const uint8_t *data, size_t data_len, int end_stream);
