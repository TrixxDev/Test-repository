/* virtio-net — see virtio_net.h.
 *
 * Phase 1: detection.  Phase 2: TX virtqueue.  Phase 3: RX path + IRQ.
 *
 * Legacy virtio-pci: device registers + one virtqueue per direction behind BAR0
 * (I/O space). A virtqueue = descriptor table + "available" ring (driver->device)
 * + "used" ring (device->driver), in one contiguous, page-aligned, physically-
 * addressed region. The rings and packet buffers live in identity-mapped static
 * memory (phys == virt on this kernel), so no DMA allocator is needed yet.
 * virtio-net queue 0 = RX, queue 1 = TX. */
#include "virtio_net.h"
#include "pci.h"
#include "io.h"
#include "isr.h"
#include "kio.h"
#include "string.h"

#define VIRTIO_VENDOR   0x1AF4
#define VIRTIO_NET_DEV  0x1000      /* legacy / transitional virtio-net */

/* Legacy virtio-pci I/O registers, relative to the BAR0 I/O base. */
#define R_HOST_FEATURES   0x00
#define R_GUEST_FEATURES  0x04
#define R_QUEUE_PFN       0x08
#define R_QUEUE_SIZE      0x0C
#define R_QUEUE_SELECT    0x0E
#define R_QUEUE_NOTIFY    0x10
#define R_STATUS          0x12
#define R_ISR             0x13
#define R_NET_MAC         0x14

#define VS_ACK        0x01
#define VS_DRIVER     0x02
#define VS_DRIVER_OK  0x04
#define VS_FAILED     0x80

#define DESC_F_NEXT   0x1
#define DESC_F_WRITE  0x2           /* device writes into the buffer (RX) */

#define RX_QUEUE      0
#define TX_QUEUE      1
#define VRING_ALIGN   4096
#define MAX_QSIZE     256
#define VRING_BYTES   16384         /* fits a 256-entry legacy vring (~10 KiB) */
#define NET_HDR_LEN   10            /* legacy virtio_net_hdr, no MRG_RXBUF */
#define ETH_MIN       14            /* a frame shorter than this has no header */
#define ETH_MAX       1514          /* DIX Ethernet payload cap (no jumbo/FCS) */
#define RX_BUFS       16            /* receive buffers we post */
#define RX_BUF_SZ     2048

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vq {
    int       index;
    uint16_t  size;
    struct vring_desc        *desc;
    volatile uint16_t        *avail_idx, *avail_ring;
    volatile uint16_t        *used_idx;
    volatile struct vring_used_elem *used_ring;
    uint16_t  last_used;        /* used entries we've consumed */
};

/* Identity-mapped, page-aligned rings + packet buffers. */
static __attribute__((aligned(VRING_ALIGN))) uint8_t tx_vring[VRING_BYTES];
static __attribute__((aligned(VRING_ALIGN))) uint8_t rx_vring[VRING_BYTES];
static __attribute__((aligned(16)))          uint8_t tx_buf[NET_HDR_LEN + ETH_MAX];
static __attribute__((aligned(16)))          uint8_t rx_bufs[RX_BUFS][RX_BUF_SZ];

static pci_dev_t dev;
static uint16_t  io_base;
static uint8_t   mac[6];
static int       present;
static struct vq txq, rxq;
static struct net_stats stats;      /* interface counters (see net_get_stats) */

static inline void barrier(void) { __asm__ volatile("" ::: "memory"); }
static uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

int            virtio_net_present(void) { return present; }
const uint8_t *virtio_net_mac(void)     { return mac; }

void net_get_stats(struct net_stats *out)
{
    if (!out)
        return;
    *out = stats;               /* snapshot of plain counters */
    out->up = present ? 1u : 0u;
    for (int i = 0; i < 6; i++)
        out->mac[i] = mac[i];
}

/* Carve a virtqueue out of `buf` and register its page number with the device. */
static int vq_setup(struct vq *q, uint8_t *buf, int index)
{
    outw(io_base + R_QUEUE_SELECT, (uint16_t)index);
    uint16_t n = inw(io_base + R_QUEUE_SIZE);
    if (n == 0 || n > MAX_QSIZE)
        return -1;
    uint32_t avail_off = (uint32_t)n * sizeof(struct vring_desc);
    uint32_t used_off  = align_up(avail_off + 4 + 2 * (uint32_t)n + 2, VRING_ALIGN);
    if (used_off + 4 + 8 * (uint32_t)n + 2 > VRING_BYTES)
        return -1;

    memset(buf, 0, VRING_BYTES);
    q->index     = index;
    q->size      = n;
    q->desc      = (struct vring_desc *)buf;
    q->avail_idx = (volatile uint16_t *)(buf + avail_off + 2);
    q->avail_ring= (volatile uint16_t *)(buf + avail_off + 4);
    q->used_idx  = (volatile uint16_t *)(buf + used_off + 2);
    q->used_ring = (volatile struct vring_used_elem *)(buf + used_off + 4);
    q->last_used = 0;

    outl(io_base + R_QUEUE_PFN, (uint32_t)buf >> 12);
    kprintf("[virtio] queue %d size=%d ring phys=0x%x\n", index, n, (uint32_t)buf);
    return 0;
}

int net_send_frame(const void *data, unsigned len)
{
    if (!present || !data || len < ETH_MIN || len > ETH_MAX) {
        stats.tx_dropped++;                     /* malformed: never hits the wire */
        return -1;
    }

    memset(tx_buf, 0, NET_HDR_LEN);             /* zeroed legacy net header */
    memcpy(tx_buf + NET_HDR_LEN, data, len);

    txq.desc[0].addr  = (uint64_t)(uint32_t)tx_buf;   /* identity: phys == virt */
    txq.desc[0].len   = NET_HDR_LEN + len;
    txq.desc[0].flags = 0;
    txq.desc[0].next  = 0;

    txq.avail_ring[*txq.avail_idx % txq.size] = 0;
    barrier();
    (*txq.avail_idx)++;
    barrier();
    outw(io_base + R_QUEUE_NOTIFY, TX_QUEUE);

    uint16_t target = *txq.avail_idx;
    int done = 0;
    for (int spin = 0; spin < 4000000; spin++) {
        if (*txq.used_idx == target) { done = 1; break; }
        barrier();
    }
    if (!done) {
        stats.tx_errors++;                      /* device never completed the buffer */
        kprintf("[DBG-TX] net_send_frame FAILED (spin exhausted) tx_errors=%u tx_packets=%u len=%u\n",
                stats.tx_errors, stats.tx_packets, len);
        return -1;
    }
    stats.tx_packets++;
    stats.tx_bytes += len;
    return 0;
}

/* Hand RX descriptor `id` back to the device so it can refill that buffer. */
static void rx_recycle(uint32_t id)
{
    rxq.avail_ring[*rxq.avail_idx % rxq.size] = (uint16_t)id;
    barrier();
    (*rxq.avail_idx)++;
    barrier();
    outw(io_base + R_QUEUE_NOTIFY, RX_QUEUE);
}

int net_recv_frame(void *buf, unsigned cap)
{
    if (!present || !buf || cap == 0)
        return 0;

    /* Drain the used ring until we find one plausible frame to return, or it is
     * empty. Every entry we pull is recycled, so a burst of runts/garbage can
     * never wedge the ring or hide the next good frame behind them. */
    while (rxq.last_used != *rxq.used_idx) {
        struct vring_used_elem e = rxq.used_ring[rxq.last_used % rxq.size];
        uint32_t id  = e.id;
        uint32_t len = e.len;
        rxq.last_used++;

        if (id >= RX_BUFS) {        /* device handed back a bogus descriptor id */
            stats.rx_dropped++;
            continue;               /* can't recycle what we can't address */
        }

        /* The device-reported length must cover the virtio header + a minimal
         * Ethernet header, and must not exceed our buffer or the wire MTU. */
        int ok = 1;
        unsigned payload = 0;
        if (len < NET_HDR_LEN + ETH_MIN) {
            stats.rx_errors++; ok = 0;          /* runt */
        } else if (len > RX_BUF_SZ || len - NET_HDR_LEN > ETH_MAX) {
            stats.rx_errors++; ok = 0;          /* oversize / impossible */
        } else {
            payload = len - NET_HDR_LEN;
        }

        if (ok) {
            unsigned n = payload < cap ? payload : cap;
            memcpy(buf, rx_bufs[id] + NET_HDR_LEN, n);
            rx_recycle(id);
            stats.rx_packets++;
            stats.rx_bytes += payload;
            return (int)n;
        }
        rx_recycle(id);             /* drop the bad frame, reuse the buffer */
    }
    return 0;                       /* ring empty */
}

static void on_virtio_irq(registers_t *regs)
{
    (void)regs;
    (void)inb(io_base + R_ISR);   /* reading ISR acks the device interrupt */
    stats.rx_irqs++;              /* RX is polled for now; the ISR only acks  */
}

/* Post all RX buffers so the device can fill them, then notify. */
static void rx_fill(void)
{
    for (int i = 0; i < RX_BUFS; i++) {
        rxq.desc[i].addr  = (uint64_t)(uint32_t)rx_bufs[i];
        rxq.desc[i].len   = RX_BUF_SZ;
        rxq.desc[i].flags = DESC_F_WRITE;        /* device writes the frame here */
        rxq.desc[i].next  = 0;
        rxq.avail_ring[i] = (uint16_t)i;
    }
    barrier();
    *rxq.avail_idx = RX_BUFS;
    barrier();
    outw(io_base + R_QUEUE_NOTIFY, RX_QUEUE);
}

void virtio_net_init(void)
{
    memset(&stats, 0, sizeof(stats));
    if (!pci_find(VIRTIO_VENDOR, VIRTIO_NET_DEV, &dev)) {
        kprintf("[net] no virtio-net device on PCI\n");
        return;
    }
    pci_enable_io_bus_master(&dev);
    io_base = pci_bar0_io(&dev);

    outb(io_base + R_STATUS, 0);                            /* reset */
    outb(io_base + R_STATUS, VS_ACK);
    outb(io_base + R_STATUS, VS_ACK | VS_DRIVER);

    uint32_t host_features = inl(io_base + R_HOST_FEATURES);
    outl(io_base + R_GUEST_FEATURES, 0);                    /* legacy header, no offloads */

    for (int i = 0; i < 6; i++)
        mac[i] = inb(io_base + R_NET_MAC + i);

    if (vq_setup(&rxq, rx_vring, RX_QUEUE) != 0 ||
        vq_setup(&txq, tx_vring, TX_QUEUE) != 0) {
        outb(io_base + R_STATUS, VS_FAILED);
        kprintf("[net] virtio-net queue setup failed\n");
        return;
    }

    register_interrupt_handler(43, on_virtio_irq);          /* IRQ11 -> vector 43 */
    outb(io_base + R_STATUS, VS_ACK | VS_DRIVER | VS_DRIVER_OK);
    present = 1;
    rx_fill();

    kprintf("[net] virtio-net up: io=0x%x irq=%d mac=%x:%x:%x:%x:%x:%x feat=0x%x\n",
            io_base, dev.irq, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            host_features);
    /* Protocol bring-up + traffic now live in the net layer (net_selftest). */
}
