/* FAT32 read-only filesystem driver (over the ATA disk). */
#pragma once
#include "vfs.h"

/* Read the BPB from the disk and return the root directory node, or NULL if no
 * valid FAT32 filesystem is found. */
vfs_node_t *fat32_mount(void);
