/* virtio-net (legacy/transitional virtio-pci) — Phase 1: detection only.
 *
 * Brings the PCI device far enough to read its MAC and prove the PCI + virtio-pci
 * I/O path works. Virtqueue setup and net_send_frame/net_recv_frame come next. */
#pragma once
#include <stdint.h>

void           virtio_net_init(void);     /* probe PCI; bring the device to DRIVER */
int            virtio_net_present(void);   /* 1 if a virtio-net device was found */
const uint8_t *virtio_net_mac(void);       /* 6-byte MAC (valid once present) */
