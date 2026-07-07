/* virtio-net (legacy/transitional virtio-pci).
 *
 * Phase 1: detection (MAC).  Phase 2: TX virtqueue transport.  Phase 3: RX path
 * + IRQ.  The vrings live in identity-mapped static memory (phys == virt on this
 * kernel), so no DMA allocator is needed yet. The transport exposes two raw
 * primitives, net_send_frame()/net_recv_frame(), on top of which higher layers
 * (Ethernet, ARP, IPv4, ...) are built. All inbound length/index fields supplied
 * by the device are bounds-checked here, and per-interface counters are kept so
 * the upper layers (and Settings -> System) can observe traffic and drops. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "syscall_abi.h"        /* struct net_stats (shared kernel/user ABI) */

void           virtio_net_init(void);      /* probe PCI, bring up RX+TX, ARP probe */
int            virtio_net_present(void);    /* 1 if a virtio-net device is up */
const uint8_t *virtio_net_mac(void);        /* our 6-byte MAC */

/* Transmit one Ethernet frame (without FCS). Returns 0 on success, -1 on error.
 * Blocks (bounded) until the device marks the buffer used. */
int            net_send_frame(const void *data, unsigned len);

/* Poll the RX ring for one inbound Ethernet frame (virtio header stripped).
 * Returns the frame length in bytes (>0), or 0 if the ring is empty. Runt /
 * oversize / garbage frames are dropped (and counted) internally, so a nonzero
 * return is always a plausible Ethernet frame and a zero return always means
 * "nothing pending right now". */
int            net_recv_frame(void *buf, unsigned cap);

/* Snapshot the interface counters into *out (zeroed if no NIC is present). */
void           net_get_stats(struct net_stats *out);
