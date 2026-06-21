/* DNS resolver over UDP — Phase 7.5.
 *
 * The API is typed from the start (dns_query takes a record type) so adding
 * AAAA/CNAME later won't break callers, even though only A is parsed today.
 * Queries go to the SLIRP virtual DNS server (10.0.2.3:53), which forwards to
 * the host's resolver. Synchronous: dns_query() sends and pumps the RX path
 * until the answer arrives or it times out. */
#pragma once
#include <stdint.h>

/* DNS record types (RFC 1035 + AAAA). */
#define DNS_A       1
#define DNS_NS      2
#define DNS_CNAME   5
#define DNS_AAAA    28

/* Resolve `name` for record `type`. For DNS_A, *out_ip is filled (host order) on
 * success. Returns 0 on success, -1 on timeout / no matching record / error. */
int dns_query(const char *name, uint16_t type, uint32_t *out_ip);
