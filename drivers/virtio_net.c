/* virtio-net — see virtio_net.h. Phase 1: probe + MAC. */
#include "virtio_net.h"
#include "pci.h"
#include "io.h"
#include "kio.h"

#define VIRTIO_VENDOR   0x1AF4
#define VIRTIO_NET_DEV  0x1000      /* legacy / transitional virtio-net */

/* Legacy virtio-pci I/O registers, relative to the BAR0 I/O base. */
#define VIRTIO_STATUS       0x12    /* device status (8-bit)                 */
#define VIRTIO_NET_CFG_MAC  0x14    /* device config: MAC[6] (MSI-X disabled) */

#define ST_ACK     0x01             /* guest noticed the device   */
#define ST_DRIVER  0x02             /* guest has a driver for it   */

static pci_dev_t dev;
static uint16_t  io_base;
static uint8_t   mac[6];
static int       present;

int            virtio_net_present(void) { return present; }
const uint8_t *virtio_net_mac(void)     { return mac; }

void virtio_net_init(void)
{
    if (!pci_find(VIRTIO_VENDOR, VIRTIO_NET_DEV, &dev)) {
        kprintf("[net] no virtio-net device on PCI\n");
        return;
    }
    pci_enable_io_bus_master(&dev);
    io_base = pci_bar0_io(&dev);

    /* Start the virtio handshake: reset, then acknowledge we have a driver. */
    outb(io_base + VIRTIO_STATUS, 0);
    outb(io_base + VIRTIO_STATUS, ST_ACK);
    outb(io_base + VIRTIO_STATUS, ST_ACK | ST_DRIVER);

    for (int i = 0; i < 6; i++)
        mac[i] = inb(io_base + VIRTIO_NET_CFG_MAC + i);

    present = 1;
    kprintf("[net] virtio-net at %x:%x.%x io=0x%x irq=%d mac=%x:%x:%x:%x:%x:%x\n",
            dev.bus, dev.slot, dev.func, io_base, dev.irq,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
