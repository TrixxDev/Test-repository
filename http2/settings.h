/* HTTP/2 SETTINGS frame (RFC 7540 §6.5) — Phase 17.1.1.
 *
 * Just enough to complete the mandatory connection-establishment exchange:
 * build an empty SETTINGS frame (the simplest valid client announcement --
 * no special preferences) and a SETTINGS ACK, and validate that a received
 * SETTINGS frame's payload is at least shaped correctly. Individual
 * parameter *values* aren't interpreted yet -- no later phase needs one
 * yet either, so there's nothing to act on beyond "well-formed or not." */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "frame.h"

/* Settings identifiers (RFC 7540 §6.5.2) -- defined for completeness/future
 * use; Phase 17.1.1 doesn't read individual parameter values yet. */
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x1
#define H2_SETTINGS_ENABLE_PUSH            0x2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define H2_SETTINGS_MAX_FRAME_SIZE         0x5
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE   0x6

#define H2_SETTINGS_PARAM_LEN 6   /* one parameter: uint16 identifier + uint32 value */

/* Build an empty SETTINGS frame (stream 0, no parameters) into `out`.
 * Returns its length or -1 (see h2_write_frame_header()). */
int h2_build_settings_empty(uint8_t *out, size_t cap);

/* Build a SETTINGS ACK frame (stream 0, ACK flag set, empty payload -- RFC
 * 7540 §6.5 requires exactly this shape; a nonzero-length SETTINGS ACK is a
 * connection error on the *sending* side, so this builder can't produce an
 * invalid one). Returns its length or -1. */
int h2_build_settings_ack(uint8_t *out, size_t cap);

/* Is `h` (an already-parsed frame header) a SETTINGS ACK, as opposed to a
 * "real" SETTINGS frame carrying parameters? */
static inline int h2_is_settings_ack(const h2_frame_header *h)
{
    return h->type == H2_TYPE_SETTINGS && (h->flags & H2_FLAG_ACK) != 0;
}

/* Is `length` a structurally valid SETTINGS payload length (RFC 7540 §6.5:
 * "A badly formed or incomplete SETTINGS frame MUST be treated as ... a
 * connection error"; the payload is a sequence of 6-byte parameters, so its
 * length must be an exact multiple of 6)? */
static inline int h2_settings_payload_valid(uint32_t length)
{
    return (length % H2_SETTINGS_PARAM_LEN) == 0;
}
