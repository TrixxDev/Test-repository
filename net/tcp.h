/* TCP — Phase 1: client connect() only (the three-way handshake).
 *
 * Strictly scoped: the TCB and the state enum are the full RFC 793 shape from day
 * one (so nothing has to be rewritten later), but only CLOSED -> SYN_SENT ->
 * ESTABLISHED are implemented. No listen/accept, no data transfer, no
 * retransmission, congestion control, SACK, window scaling or keepalive yet.
 * A single global connection is enough to prove the handshake. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Full RFC 793 state set; only CLOSED / SYN_SENT / ESTABLISHED are reached in
 * Phase 1. The rest are declared so later phases don't renumber the enum. */
enum tcp_state {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
};

/* Transmission Control Block. Several fields are unused in Phase 1 (window,
 * snd_una bookkeeping for unsent data, ...) but present so the layout is stable. */
struct tcp_tcb {
    uint32_t local_ip,  remote_ip;
    uint16_t local_port, remote_port;

    uint32_t snd_una;       /* oldest unacknowledged sequence number   */
    uint32_t snd_nxt;       /* next sequence number to send            */
    uint32_t rcv_nxt;       /* next sequence number expected to receive */

    uint32_t iss;           /* our initial send sequence number        */
    uint32_t irs;           /* peer's initial receive sequence number  */

    uint16_t snd_wnd;       /* peer's advertised window                */
    uint16_t rcv_wnd;       /* our advertised window                   */

    uint8_t  state;
};

void        tcp_init(void);

/* Begin a connection to host-order `dst`:`port`: send SYN, enter SYN_SENT.
 * Returns 0 if the SYN was transmitted, -1 on error. The caller pumps the RX
 * path (net_poll) and watches tcp_state() for ESTABLISHED. */
int         tcp_connect(uint32_t dst, uint16_t port);

/* Current state of the (single) connection. */
int         tcp_state(void);
const char *tcp_state_name(int state);

/* Handle one TCP segment (IPv4 payload) from host-order `src`. */
void        tcp_input(uint32_t src, const void *segment, size_t len);
