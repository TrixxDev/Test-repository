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
#define ETH_MAX       1514
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
static volatile unsigned rx_irqs;   /* diagnostics: device interrupts seen */

static inline void barrier(void) { __asm__ volatile("" ::: "memory"); }
static uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

int            virtio_net_present(void) { return present; }
const uint8_t *virtio_net_mac(void)     { return mac; }

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
    if (!present || len == 0 || len > ETH_MAX)
        return -1;

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
    for (int spin = 0; spin < 4000000 && *txq.used_idx != target; spin++)
        barrier();
    return 0;
}

int net_recv_frame(void *buf, unsigned cap)
{
    if (!present || rxq.last_used == *rxq.used_idx)
        return 0;                               /* nothing received */

    struct vring_used_elem e = rxq.used_ring[rxq.last_used % rxq.size];
    uint32_t id  = e.id;
    uint32_t len = e.len;
    int out = 0;
    if (id < RX_BUFS && len > NET_HDR_LEN) {     /* strip the virtio_net_hdr */
        out = (int)(len - NET_HDR_LEN);
        if ((unsigned)out > cap) out = (int)cap;
        memcpy(buf, rx_bufs[id] + NET_HDR_LEN, (size_t)out);
    }
    rxq.last_used++;

    /* Recycle the buffer back to the device. */
    if (id < RX_BUFS) {
        rxq.avail_ring[*rxq.avail_idx % rxq.size] = (uint16_t)id;
        barrier();
        (*rxq.avail_idx)++;
        barrier();
        outw(io_base + R_QUEUE_NOTIFY, RX_QUEUE);
    }
    return out;
}

static void on_virtio_irq(registers_t *regs)
{
    (void)regs;
    (void)inb(io_base + R_ISR);   /* reading ISR acks the device interrupt */
    rx_irqs++;                     /* RX is polled for now; just count + ack */
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

/* Phase 3 proof: ARP-who-has 10.0.2.2 (the SLIRP gateway) to elicit a reply. */
static void arp_probe(void)
{
    uint8_t a[42];
    int n = 0;
    for (int i = 0; i < 6; i++) a[n++] = 0xFF;   /* eth dst: broadcast */
    for (int i = 0; i < 6; i++) a[n++] = mac[i]; /* eth src: us         */
    a[n++] = 0x08; a[n++] = 0x06;                /* ethertype: ARP      */
    a[n++] = 0x00; a[n++] = 0x01;                /* htype: Ethernet     */
    a[n++] = 0x08; a[n++] = 0x00;                /* ptype: IPv4         */
    a[n++] = 6; a[n++] = 4;                      /* hlen, plen          */
    a[n++] = 0x00; a[n++] = 0x01;                /* oper: request       */
    for (int i = 0; i < 6; i++) a[n++] = mac[i]; /* sender HW           */
    a[n++] = 10; a[n++] = 0; a[n++] = 2; a[n++] = 15;   /* sender IP 10.0.2.15 */
    for (int i = 0; i < 6; i++) a[n++] = 0x00;   /* target HW (unknown) */
    a[n++] = 10; a[n++] = 0; a[n++] = 2; a[n++] = 2;    /* target IP 10.0.2.2  */
    net_send_frame(a, n);

    uint8_t rb[1600];
    for (int spin = 0; spin < 40000000; spin++) {
        int r = net_recv_frame(rb, sizeof(rb));
        if (r >= 14) {
            kprintf("[net] rx %d bytes src=%x:%x:%x:%x:%x:%x type=0x%x%x\n",
                    r, rb[6], rb[7], rb[8], rb[9], rb[10], rb[11], rb[12], rb[13]);
            return;
        }
        barrier();
    }
    kprintf("[net] no frame received (rx timeout)\n");
}

void virtio_net_init(void)
{
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

    arp_probe();
}
