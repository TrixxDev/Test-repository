#include "ata.h"
#include "io.h"

/* Primary ATA bus I/O ports. */
#define ATA_DATA      0x1F0
#define ATA_ERROR     0x1F1
#define ATA_SECCOUNT  0x1F2
#define ATA_LBA_LO    0x1F3
#define ATA_LBA_MID   0x1F4
#define ATA_LBA_HI    0x1F5
#define ATA_DRIVE     0x1F6
#define ATA_STATUS    0x1F7
#define ATA_COMMAND   0x1F7
#define ATA_CONTROL   0x3F6

#define ST_ERR  0x01
#define ST_DRQ  0x08
#define ST_BSY  0x80

#define CMD_READ_PIO  0x20
#define CMD_WRITE_PIO 0x30
#define CMD_FLUSH     0xE7
#define CMD_IDENTIFY  0xEC

static void delay400(void)
{
    /* Reading the status register takes ~100ns; four reads ~= 400ns. */
    for (int i = 0; i < 4; i++)
        (void)inb(ATA_STATUS);
}

static int wait_ready(void)
{
    for (int i = 0; i < 100000; i++) {
        uint8_t s = inb(ATA_STATUS);
        if (s & ST_ERR)
            return -1;
        if (!(s & ST_BSY) && (s & ST_DRQ))
            return 0;
    }
    return -1;
}

int ata_init(void)
{
    /* Select master and issue IDENTIFY. */
    outb(ATA_DRIVE, 0xA0);
    delay400();
    outb(ATA_SECCOUNT, 0);
    outb(ATA_LBA_LO, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HI, 0);
    outb(ATA_COMMAND, CMD_IDENTIFY);

    if (inb(ATA_STATUS) == 0)
        return 0;   /* no drive */

    /* Wait for BSY to clear. */
    for (int i = 0; i < 100000; i++)
        if (!(inb(ATA_STATUS) & ST_BSY))
            break;

    /* A non-ATA / no device leaves nonzero LBA mid/hi. */
    if (inb(ATA_LBA_MID) != 0 || inb(ATA_LBA_HI) != 0)
        return 0;

    if (wait_ready() != 0)
        return 0;

    /* Discard the 256-word identification block. */
    for (int i = 0; i < 256; i++)
        (void)inw(ATA_DATA);

    return 1;
}

int ata_read_sectors(uint32_t lba, uint8_t count, void *buf)
{
    uint16_t *out = (uint16_t *)buf;
    uint32_t total = count ? count : 256;

    /* Wait until not busy. */
    for (int i = 0; i < 100000; i++)
        if (!(inb(ATA_STATUS) & ST_BSY))
            break;

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));   /* master + LBA + high nibble */
    delay400();
    outb(ATA_SECCOUNT, count);
    outb(ATA_LBA_LO,  (uint8_t)(lba & 0xFF));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI,  (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_COMMAND, CMD_READ_PIO);

    for (uint32_t s = 0; s < total; s++) {
        if (wait_ready() != 0)
            return -1;
        for (int i = 0; i < 256; i++)
            out[s * 256 + i] = inw(ATA_DATA);
        delay400();
    }
    return 0;
}

int ata_write_sectors(uint32_t lba, uint8_t count, const void *buf)
{
    const uint16_t *in = (const uint16_t *)buf;
    uint32_t total = count ? count : 256;

    for (int i = 0; i < 100000; i++)
        if (!(inb(ATA_STATUS) & ST_BSY))
            break;

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));   /* master + LBA + high nibble */
    delay400();
    outb(ATA_SECCOUNT, count);
    outb(ATA_LBA_LO,  (uint8_t)(lba & 0xFF));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI,  (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_COMMAND, CMD_WRITE_PIO);

    for (uint32_t s = 0; s < total; s++) {
        if (wait_ready() != 0)
            return -1;
        for (int i = 0; i < 256; i++)
            outw(ATA_DATA, in[s * 256 + i]);
        delay400();             /* required between sectors on PIO writes */
    }

    /* Flush the drive's write cache so the data is durable. */
    outb(ATA_COMMAND, CMD_FLUSH);
    for (int i = 0; i < 100000; i++)
        if (!(inb(ATA_STATUS) & ST_BSY))
            break;
    return 0;
}
