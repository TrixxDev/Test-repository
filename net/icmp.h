/* ICMP — Phase 6 (echo only).
 *
 * Two halves: a responder (reply to incoming echo requests for our IP, so the
 * host can ping us) and a client (send echo requests and match the replies, so
 * we can ping the gateway). Echo is all that's needed for the ping milestone;
 * unreachable/time-exceeded come later if anything needs them. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define ICMP_ECHO_REPLY    0
#define ICMP_ECHO_REQUEST  8

/* Handle one ICMP message (IPv4 payload) from host-order `src`. */
void icmp_input(uint32_t src, const void *payload, size_t len);

/* Send an echo request (`id`/`seq` host order) with `dlen` payload bytes to
 * host-order `dst`. Returns 0 on success, -1 if not sendable yet (ARP pending). */
int  icmp_send_echo(uint32_t dst, uint16_t id, uint16_t seq,
                    const void *data, size_t dlen);

/* Reply matcher for the ping client: returns 1 (and clears the latch) if an echo
 * reply matching (`id`, `seq`) has arrived since the last call. */
int  icmp_take_reply(uint16_t id, uint16_t seq);
