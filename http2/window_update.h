/* HTTP/2 WINDOW_UPDATE frame (RFC 7540 §6.9) — Phase 17.4.3.
 *
 * Flow control: the receiver of DATA frames tells the sender, via
 * WINDOW_UPDATE, how many more payload bytes it's willing to receive --
 * either for one specific stream, or (stream_id 0) for the whole
 * connection. Both this file's functions are direction-agnostic (parse
 * what arrives, build what to send); the actual window bookkeeping --
 * decrementing on DATA, deciding when a top-up is due -- lives in
 * user/httpsget.c's h2_fetch(), the same way frame.h/data.h stay generic
 * while httpsget.c owns the policy built on top of them. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "frame.h"

/* Parse a WINDOW_UPDATE frame's payload: a single 31-bit unsigned
 * increment (the reserved top bit is ignored on receipt, per RFC 7540
 * §6.9's own text, the same "reserved bits MUST be ignored" convention
 * frame.h's own stream_id parsing already follows). Returns 0 and sets
 * *increment, or -1 if `payload_len` isn't exactly 4 bytes, or the
 * increment is 0 -- RFC 7540 §6.9: "A receiver MUST treat the receipt of
 * a WINDOW_UPDATE frame with a flow-control window increment of 0 as a
 * stream error... or connection error", never a value to silently accept. */
int h2_window_update_parse(const uint8_t *payload, size_t payload_len, uint32_t *increment);

/* Build a WINDOW_UPDATE frame (header + 4-byte payload) into `out` for
 * `stream_id` (0 for the whole connection), incrementing its window by
 * `increment` (1..0x7FFFFFFF -- RFC 7540 §6.9's own valid range). Returns
 * the total frame length, or -1 on a capacity error or an out-of-range
 * increment. */
int h2_window_update_build(uint8_t *out, size_t cap, uint32_t stream_id, uint32_t increment);
