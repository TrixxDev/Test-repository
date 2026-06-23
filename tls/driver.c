/* TLS 1.3 handshake driver — see driver.h. */
#include "driver.h"

/* Write every byte, tolerating short writes (the "tls_send_all" contract): a
 * transport that reports a partial count is looped until the flight is out. A
 * write that makes no progress (<=0) is a hard error rather than a spin. */
static int send_all(const tls_transport *t, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int w = t->write(t->ctx, buf + sent, len - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

int tls_driver_handshake(tls_conn *conn, tls_record_reader *reader,
                         const tls_transport *t, uint8_t *scratch, size_t scratch_len)
{
    /* 1. ClientHello (plaintext handshake record). */
    int chl = tls_conn_start(conn, scratch, scratch_len);
    if (chl < 0) return TLS_DRIVE_PROTOCOL;
    if (send_all(t, scratch, (size_t)chl) != 0) return TLS_DRIVE_WRITE_ERR;

    /* 2. Consume the server flight until the FSM reaches CONNECTED. Each pass
     * drains every record currently framed by the reader, then reads more. */
    for (;;) {
        const uint8_t *rec;
        size_t reclen;
        int rc;
        while ((rc = tls_reader_next(reader, &rec, &reclen)) != 0) {
            if (rc < 0) return TLS_DRIVE_MALFORMED;     /* record length over the wire limit */

            /* `rec` points into the reader's buffer; `scratch` is free to receive
             * any emitted client Finished (the read bytes in it were already
             * copied into the reader by feed). */
            size_t out_len = 0;
            int cc = tls_conn_recv_record(conn, rec, reclen, scratch, scratch_len, &out_len);
            if (cc < 0) return TLS_DRIVE_PROTOCOL;      /* FSM/record error; reason in the trace */
            if (out_len > 0 && send_all(t, scratch, out_len) != 0) return TLS_DRIVE_WRITE_ERR;
            if (tls_conn_connected(conn)) return TLS_DRIVE_OK;   /* Finished is on the wire */
        }

        /* Reader needs more bytes. Pull the next chunk from the transport. */
        int n = t->read(t->ctx, scratch, scratch_len);
        if (n == 0) return TLS_DRIVE_EOF;               /* peer closed before CONNECTED */
        if (n < 0)  return TLS_DRIVE_READ_ERR;
        if (tls_reader_feed(reader, scratch, (size_t)n) != 0) return TLS_DRIVE_OVERFLOW;
    }
}
