/* virtio-net (legacy/transitional virtio-pci).
 *
 * Phase 1: detection (MAC).  Phase 2: TX-only virtqueue transport — bring the
 * device to DRIVER_OK, set up the transmit queue, and send raw Ethernet frames.
 * RX + IRQ completions come next. The vrings live in identity-mapped static
 * memory (phys == virt on this kernel), so no DMA allocator is needed yet. */
#pragma once
#include <stdint.h>
#include <stddef.h>

void           virtio_net_init(void);      /* probe PCI, bring up TX, send a test frame */
int            virtio_net_present(void);    /* 1 if a virtio-net device is up */
const uint8_t *virtio_net_mac(void);        /* our 6-byte MAC */

/* Transmit one Ethernet frame (without FCS). Returns 0 on success, -1 on error.
 * Blocks (bounded) until the device marks the buffer used. */
int            net_send_frame(const void *data, unsigned len);
