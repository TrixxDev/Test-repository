/* Minimal PCI configuration-space access (mechanism #1) + device lookup.
 *
 * Just enough to find a virtio device on QEMU's `pc` machine: enumerate the bus,
 * read vendor/device/BAR/IRQ, and flip on I/O + bus-mastering. No bridges, no
 * capability walking beyond what virtio-legacy needs. */
#pragma once
#include <stdint.h>

typedef struct {
    int      found;
    uint8_t  bus, slot, func;
    uint16_t vendor, device;
    uint32_t bar0;          /* raw BAR0 (low bit set => I/O space, as virtio-legacy uses) */
    uint8_t  irq;           /* interrupt line (legacy INTx) */
} pci_dev_t;

uint32_t pci_config_read32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off);
uint16_t pci_config_read16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off);
void     pci_config_write32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint32_t val);
void     pci_config_write16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint16_t val);

/* Scan for the first device matching (vendor, device); fills *out. Returns 1 if
 * found. */
int      pci_find(uint16_t vendor, uint16_t device, pci_dev_t *out);

/* Enable I/O space (bit0) + bus mastering (bit2) in the command register. */
void     pci_enable_io_bus_master(const pci_dev_t *d);

/* I/O-space base address from BAR0 (mask off the low type bits). */
static inline uint16_t pci_bar0_io(const pci_dev_t *d) { return (uint16_t)(d->bar0 & ~0x3u); }
