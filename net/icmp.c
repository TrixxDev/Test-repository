/* ICMP echo (ping) — responder + client. See icmp.h. */
#include "icmp.h"
#include "ipv4.h"
#include "inet.h"
#include "string.h"

struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;            /* network order */
    uint16_t seq;           /* network order */
    /* echo data follows */
} __attribute__((packed));

#define ICMP_MAX_DATA   1024

/* Last echo reply we saw, latched for the ping client to consume. */
static volatile int      reply_pending;
static volatile uint16_t reply_id, reply_seq;

static uint8_t echo_tx[sizeof(struct icmp_hdr) + ICMP_MAX_DATA];

int icmp_send_echo(uint32_t dst, uint16_t id, uint16_t seq,
                   const void *data, size_t dlen)
{
    if (dlen > ICMP_MAX_DATA)
        return -1;

    struct icmp_hdr *h = (struct icmp_hdr *)echo_tx;
    h->type     = ICMP_ECHO_REQUEST;
    h->code     = 0;
    h->checksum = 0;
    h->id       = htons(id);
    h->seq      = htons(seq);
    if (dlen)
        memcpy(echo_tx + sizeof(*h), data, dlen);

    unsigned total = sizeof(*h) + (unsigned)dlen;
    h->checksum = inet_csum(echo_tx, total);
    return ipv4_send(dst, IPPROTO_ICMP, echo_tx, total);
}

void icmp_input(uint32_t src, const void *payload, size_t len)
{
    if (len < sizeof(struct icmp_hdr))
        return;
    if (inet_csum(payload, (uint32_t)len) != 0)
        return;                                 /* corrupt ICMP message */

    const struct icmp_hdr *h = (const struct icmp_hdr *)payload;

    if (h->type == ICMP_ECHO_REPLY) {
        /* Latch it for the ping client to match. */
        reply_id   = ntohs(h->id);
        reply_seq  = ntohs(h->seq);
        reply_pending = 1;
        return;
    }

    if (h->type == ICMP_ECHO_REQUEST) {
        /* Reflect: same id/seq/data, type -> reply, recompute checksum. */
        static uint8_t echo_rx[sizeof(struct icmp_hdr) + ICMP_MAX_DATA];
        unsigned n = len > sizeof(echo_rx) ? sizeof(echo_rx) : (unsigned)len;
        memcpy(echo_rx, payload, n);
        struct icmp_hdr *r = (struct icmp_hdr *)echo_rx;
        r->type     = ICMP_ECHO_REPLY;
        r->code     = 0;
        r->checksum = 0;
        r->checksum = inet_csum(echo_rx, n);
        ipv4_send(src, IPPROTO_ICMP, echo_rx, n);
    }
}

int icmp_take_reply(uint16_t id, uint16_t seq)
{
    if (reply_pending && reply_id == id && reply_seq == seq) {
        reply_pending = 0;
        return 1;
    }
    return 0;
}
