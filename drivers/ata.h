/* ATA (IDE) disk driver, primary bus, PIO mode, LBA28. */
#pragma once
#include <stdint.h>

/* Probe the primary master. Returns 1 if a disk is present, 0 otherwise. */
int ata_init(void);

/* Read `count` 512-byte sectors starting at LBA into buf. 0 on success. */
int ata_read_sectors(uint32_t lba, uint8_t count, void *buf);

/* Write `count` 512-byte sectors starting at LBA from buf (flushes the write
 * cache afterwards). 0 on success. */
int ata_write_sectors(uint32_t lba, uint8_t count, const void *buf);
