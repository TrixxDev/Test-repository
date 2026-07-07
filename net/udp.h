/* UDP — Phase 7 (minimal datagrams, no sockets yet).
 *
 * Two calls, exactly as planned: udp_send() to fire a datagram and udp_bind() to
 * register a handler for an inbound port. This is the substrate DNS/NTP/syslog/
 * discovery sit on; user-visible sockets come later. UDP checksums are optional
 * over IPv4 (RFC 768), so TX sends 0 ("not computed") and RX only verifies when a
 * non-zero checksum is present. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Called for each datagram delivered to a bound port. `src`/`src_port` are host
 * order; `data`/`len` are the UDP payload. */
typedef void (*udp_handler_t)(uint32_t src, uint16_t src_port,
                              const void *data, size_t len);

void udp_init(void);

/* Send `len` payload bytes from `src_port` to host-order `dst`:`dst_port`.
 * Returns 0 on success, -1 if not sendable yet (ARP pending) or on error. */
int  udp_send(uint32_t dst, uint16_t src_port, uint16_t dst_port,
              const void *payload, size_t len);

/* Register `handler` for inbound datagrams to `port`. Returns 0 / -1 (table
 * full). Re-binding a port replaces its handler. */
int  udp_bind(uint16_t port, udp_handler_t handler);

/* Parse + dispatch one UDP segment (IPv4 payload) from host-order `src`. */
void udp_input(uint32_t src, const void *segment, size_t len);
