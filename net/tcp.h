/* TCP — client connections over the full RFC 793 state machine.
 *
 * Connections live in a fixed table; the API is handle-based (tcp_connect returns
 * a small integer handle used by send/recv/close/state), so several connections
 * can be open at once (Aurora Fetch today, a browser/updater/etc. tomorrow).
 * Implemented: connect (handshake), data send/recv (one in-order stream), and
 * teardown. Not yet: listen/accept, retransmission, congestion control, SACK,
 * window scaling, keepalive. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "syscall_abi.h"        /* struct tcp_stats (shared kernel/user ABI) */
#include "scheduler.h"          /* wait_queue_t */

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

#define TCP_MAX_CONN 32     /* connections open at once */

void        tcp_init(void);

/* Open a connection to host-order `dst`:`port`: send SYN, enter SYN_SENT.
 * Returns a connection handle (0..TCP_MAX_CONN-1) or -1 (table full / SYN not
 * sent). The caller pumps the RX path (net_poll) and watches tcp_state(h) for
 * ESTABLISHED. */
int         tcp_connect(uint32_t dst, uint16_t port);

/* State of connection `h` (TCP_CLOSED for an invalid/closed handle). */
int         tcp_state(int h);
const char *tcp_state_name(int state);

/* Send one segment of `len` payload bytes (PSH|ACK) on connection `h`. Returns
 * bytes queued (one segment, no retransmission), or -1. */
int         tcp_send(int h, const void *data, size_t len);

/* Copy up to `cap` received bytes out of connection `h`'s buffer (FIFO). Returns
 * the number copied (0 if none pending). */
int         tcp_recv(int h, void *buf, size_t cap);

/* Total payload bytes received on connection `h` so far. */
int         tcp_rx_total(int h);

/* Phase 18.3: bytes currently buffered and unread (non-destructive, unlike
 * tcp_recv()) -- for a readiness check, not for draining. */
int         tcp_rx_avail(int h);

/* Phase 18.1.5: the wait queue tcp_input() wakes whenever a segment changes
 * anything a blocked reader might care about (new data, FIN, RST, a state
 * change) -- NULL for an invalid handle. */
wait_queue_t *tcp_conn_waitq(int h);

/* 1 if connection `h` has no unacknowledged segment outstanding (safe to send the
 * next one under the single-segment retransmit cache). */
int         tcp_tx_idle(int h);

/* Begin an orderly close of connection `h`. From ESTABLISHED this sends FIN and
 * enters FIN_WAIT_1 (active close); from CLOSE_WAIT it sends FIN and enters
 * LAST_ACK (finishing a passive close). Returns 0 if a FIN was sent, -1. */
int         tcp_close(int h);

/* Drive time-based transitions (TIME_WAIT -> CLOSED) on all connections. */
void        tcp_tick(void);

/* Snapshot the TCP counters. */
void        tcp_get_stats(struct tcp_stats *out);

/* Handle one TCP segment (IPv4 payload) from host-order `src` (demuxed to the
 * matching connection by 4-tuple). */
void        tcp_input(uint32_t src, const void *segment, size_t len);

/* Test hook: silently drop the next data segment's first transmission, forcing a
 * retransmission (used by the self-test to exercise loss recovery). */
void        tcp_test_drop_next_data(void);
