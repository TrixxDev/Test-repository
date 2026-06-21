/* virtio-net — see virtio_net.h. Phase 2: TX-only virtqueue transport.
 *
 * Legacy virtio-pci: the device's registers and one virtqueue per direction live
 * behind BAR0 (I/O space). A virtqueue is a descriptor table + an "available" ring
 * (driver -> device) + a "used" ring (device -> driver), all in one contiguous,
 * page-aligned, physically-addressed region. We place it in an identity-mapped
 * static buffer (phys == virt here) and hand the device its page number. */
#include "virtio_net.h"
#include "pci.h"
#include "io.h"
#include "kio.h"
#include "string.h"

#define VIRTIO_VENDOR   0x1AF4
#define VIRTIO_NET_DEV  0x1000      /* legacy / transitional virtio-net */

/* Legacy virtio-pci I/O registers, relative to the BAR0 I/O base. */
#define R_HOST_FEATURES   0x00      /* 32  */
#define R_GUEST_FEATURES  0x04      /* 32  */
#define R_QUEUE_PFN       0x08      /* 32: ring phys >> 12   */
#define R_QUEUE_SIZE      0x0C      /* 16: device-chosen     */
#define R_QUEUE_SELECT    0x0E      /* 16  */
#define R_QUEUE_NOTIFY    0x10      /* 16: write queue index */
#define R_STATUS          0x12      /* 8   */
#define R_ISR             0x13      /* 8   */
#define R_NET_MAC         0x14      /* device config: MAC[6] (MSI-X off) */

#define VS_ACK        0x01
#define VS_DRIVER     0x02
#define VS_DRIVER_OK  0x04
#define VS_FAILED     0x80

#define DESC_F_NEXT   0x1
#define DESC_F_WRITE  0x2           /* device writes (RX) */

#define TX_QUEUE      1             /* virtio-net: 0 = RX, 1 = TX */
#define VRING_ALIGN   4096
#define MAX_QSIZE     256
#define VRING_BYTES   16384         /* fits a 256-entry legacy vring (~10 KiB) */
#define NET_HDR_LEN   10            /* legacy virtio_net_hdr, no MRG_RXBUF */
#define ETH_MAX       1514

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

/* Identity-mapped, page-aligned ring + a transmit staging buffer (hdr + frame). */
static __attribute__((aligned(VRING_ALIGN))) uint8_t tx_vring[VRING_BYTES];
static __attribute__((aligned(16)))          uint8_t tx_buf[NET_HDR_LEN + ETH_MAX];

static pci_dev_t dev;
static uint16_t  io_base;
static uint8_t   mac[6];
static int       present;

static uint16_t  qsize;
static struct vring_desc *desc;     /* descriptor table        */
static volatile uint16_t *avail_idx, *avail_ring;
static volatile uint16_t *used_idx;

static inline void barrier(void) { __asm__ volatile("" ::: "memory"); }
static uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

int            virtio_net_present(void) { return present; }
const uint8_t *virtio_net_mac(void)     { return mac; }

int net_send_frame(const void *data, unsigned len)
{
    if (!present || len == 0 || len > ETH_MAX)
        return -1;

    memset(tx_buf, 0, NET_HDR_LEN);             /* zeroed legacy net header */
    memcpy(tx_buf + NET_HDR_LEN, data, len);

    desc[0].addr  = (uint64_t)(uint32_t)tx_buf; /* identity-mapped: phys == virt */
    desc[0].len   = NET_HDR_LEN + len;
    desc[0].flags = 0;                           /* single, device-readable */
    desc[0].next  = 0;

    avail_ring[*avail_idx % qsize] = 0;          /* offer descriptor 0 */
    barrier();
    (*avail_idx)++;                              /* publish it */
    barrier();
    outw(io_base + R_QUEUE_NOTIFY, TX_QUEUE);    /* kick the device */

    /* Wait (bounded) until the device returns the buffer in the used ring. */
    uint16_t target = *avail_idx;
    for (int spin = 0; spin < 4000000 && *used_idx != target; spin++)
        barrier();
    return 0;
}

/* Set up the transmit virtqueue inside tx_vring and hand the device its PFN. */
static int tx_queue_setup(void)
{
    outw(io_base + R_QUEUE_SELECT, TX_QUEUE);
    qsize = inw(io_base + R_QUEUE_SIZE);
    if (qsize == 0 || qsize > MAX_QSIZE)
        return -1;

    memset(tx_vring, 0, sizeof(tx_vring));
    uint32_t avail_off = (uint32_t)qsize * sizeof(struct vring_desc);
    uint32_t used_off  = align_up(avail_off + 4 + 2 * (uint32_t)qsize + 2, VRING_ALIGN);
    if (used_off + 4 + 8 * (uint32_t)qsize + 2 > VRING_BYTES)
        return -1;

    desc       = (struct vring_desc *)tx_vring;
    avail_idx  = (volatile uint16_t *)(tx_vring + avail_off + 2);
    avail_ring = (volatile uint16_t *)(tx_vring + avail_off + 4);
    used_idx   = (volatile uint16_t *)(tx_vring + used_off + 2);

    outl(io_base + R_QUEUE_PFN, (uint32_t)tx_vring >> 12);
    kprintf("[virtio] queue %d size=%d ring phys=0x%x\n",
            TX_QUEUE, qsize, (uint32_t)tx_vring);
    return 0;
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
    outl(io_base + R_GUEST_FEATURES, 0);                    /* negotiate nothing (legacy header, no offloads) */

    for (int i = 0; i < 6; i++)
        mac[i] = inb(io_base + R_NET_MAC + i);

    if (tx_queue_setup() != 0) {
        outb(io_base + R_STATUS, VS_FAILED);
        kprintf("[net] virtio-net TX queue setup failed\n");
        return;
    }

    outb(io_base + R_STATUS, VS_ACK | VS_DRIVER | VS_DRIVER_OK);
    present = 1;
    kprintf("[net] virtio-net up: io=0x%x irq=%d mac=%x:%x:%x:%x:%x:%x feat=0x%x\n",
            io_base, dev.irq, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            host_features);

    /* Phase 2 proof: transmit one broadcast frame. It should appear in QEMU's
     * filter-dump pcap, confirming the virtqueue transport works end to end. */
    uint8_t frame[64];
    int n = 0;
    for (int i = 0; i < 6; i++) frame[n++] = 0xFF;          /* dst: broadcast */
    for (int i = 0; i < 6; i++) frame[n++] = mac[i];        /* src: us         */
    frame[n++] = 0x88; frame[n++] = 0xB5;                   /* ethertype: local-experimental */
    const char *msg = "AURORA-NET-PHASE2";
    for (int i = 0; msg[i]; i++) frame[n++] = (uint8_t)msg[i];
    while (n < 60) frame[n++] = 0;                          /* pad to min Ethernet length */
    net_send_frame(frame, n);
    kprintf("[net] sent %d-byte test frame (used idx=%d)\n", n, *used_idx);
}
