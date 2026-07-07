/* PCI configuration space (mechanism #1) — see pci.h. */
#include "pci.h"
#include "io.h"

#define PCI_ADDR 0xCF8
#define PCI_DATA 0xCFC

static uint32_t cfg_addr(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off)
{
    return 0x80000000u
         | ((uint32_t)bus  << 16)
         | ((uint32_t)slot << 11)
         | ((uint32_t)func << 8)
         | ((uint32_t)off & 0xFC);
}

uint32_t pci_config_read32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off)
{
    outl(PCI_ADDR, cfg_addr(bus, slot, func, off));
    return inl(PCI_DATA);
}

uint16_t pci_config_read16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off)
{
    uint32_t v = pci_config_read32(bus, slot, func, off);
    return (uint16_t)(v >> ((off & 2) * 8));
}

void pci_config_write32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint32_t val)
{
    outl(PCI_ADDR, cfg_addr(bus, slot, func, off));
    outl(PCI_DATA, val);
}

void pci_config_write16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint16_t val)
{
    uint32_t cur = pci_config_read32(bus, slot, func, off);
    int shift = (off & 2) * 8;
    cur = (cur & ~(0xFFFFu << shift)) | ((uint32_t)val << shift);
    pci_config_write32(bus, slot, func, off, cur);
}

int pci_find(uint16_t vendor, uint16_t device, pci_dev_t *out)
{
    for (int bus = 0; bus < 256; bus++) {
        for (int slot = 0; slot < 32; slot++) {
            uint16_t v = pci_config_read16((uint8_t)bus, (uint8_t)slot, 0, 0x00);
            if (v == 0xFFFF)
                continue;                       /* no device in this slot */
            uint8_t header = (uint8_t)(pci_config_read32((uint8_t)bus, (uint8_t)slot, 0, 0x0C) >> 16);
            int nfunc = (header & 0x80) ? 8 : 1; /* multi-function? */
            for (int func = 0; func < nfunc; func++) {
                uint16_t vid = pci_config_read16((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x00);
                if (vid != vendor)
                    continue;
                uint16_t did = pci_config_read16((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x02);
                if (did != device)
                    continue;
                out->found  = 1;
                out->bus    = (uint8_t)bus;
                out->slot   = (uint8_t)slot;
                out->func   = (uint8_t)func;
                out->vendor = vid;
                out->device = did;
                out->bar0   = pci_config_read32((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x10);
                out->irq    = (uint8_t)pci_config_read32((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x3C);
                return 1;
            }
        }
    }
    out->found = 0;
    return 0;
}

void pci_enable_io_bus_master(const pci_dev_t *d)
{
    uint16_t cmd = pci_config_read16(d->bus, d->slot, d->func, 0x04);
    cmd |= (1 << 0) | (1 << 2);                 /* I/O space + bus master */
    pci_config_write16(d->bus, d->slot, d->func, 0x04, cmd);
}
