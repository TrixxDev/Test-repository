/* TLS 1.3 session ticket storage (RFC 8446 §4.6.1) — Phase 15.7.
 *
 * No logic here, just the data shape that flows between layers: tls/conn.c
 * fills one of these in when a NewSessionTicket arrives (deriving the PSK
 * from the connection's resumption_master_secret), the caller stores it
 * however long it wants to keep it, and later hands the SAME shape back to
 * tls_client_offer_psk()/tls_conn_offer_psk() to attempt resumption on a
 * fresh connection to the same origin. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define TLS_TICKET_MAX 512   /* real-world server tickets are well under this;
                                RFC 8446 allows up to 2^16-1 */

typedef struct {
    uint32_t lifetime_secs;   /* ticket_lifetime (seconds), from the server        */
    uint32_t age_add;         /* ticket_age_add, for the obfuscated_ticket_age     */
    uint64_t obtained_ms;     /* when this ticket was received (caller's clock)   */
    uint8_t  ticket[TLS_TICKET_MAX];
    size_t   ticket_len;
    uint8_t  psk[32];         /* resumption PSK: HKDF from resumption_master_secret
                               * + this ticket's nonce (RFC 8446 §4.6.1)           */
} tls_session_ticket;
