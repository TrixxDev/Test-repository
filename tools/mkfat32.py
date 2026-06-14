#!/usr/bin/env python3
"""Build a minimal FAT32 disk image with a single file in the root directory.

Usage: mkfat32.py <out.img> <DOSNAME> <source-file>
Example: mkfat32.py disk.img HELLO.ELF user/hello.elf
"""
import struct
import sys

BPS        = 512        # bytes per sector
SPC        = 1          # sectors per cluster
RSVD       = 32         # reserved sectors
NUM_FATS   = 2
FATSZ      = 256        # sectors per FAT
TOTAL_SEC  = 32768      # 16 MiB image
ROOT_CLUS  = 2

FAT_EOC    = 0x0FFFFFFF


def dos_name(name):
    if "." in name:
        base, ext = name.split(".", 1)
    else:
        base, ext = name, ""
    return (base.upper()[:8].ljust(8) + ext.upper()[:3].ljust(3)).encode("ascii")


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("usage: mkfat32.py <out.img> <DOSNAME> <source>\n")
        sys.exit(1)

    out_path, dosname, src = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(src, "rb") as f:
        payload = f.read()

    img = bytearray(TOTAL_SEC * BPS)

    # ---- boot sector / BPB ----
    bs = img  # write into first sector
    bs[0:3]   = b"\xEB\x58\x90"
    bs[3:11]  = b"MSWIN4.1"
    struct.pack_into("<H", bs, 11, BPS)
    bs[13]    = SPC
    struct.pack_into("<H", bs, 14, RSVD)
    bs[16]    = NUM_FATS
    struct.pack_into("<H", bs, 17, 0)        # root entry count (0 for FAT32)
    struct.pack_into("<H", bs, 19, 0)        # total sectors 16 (0 -> use 32)
    bs[21]    = 0xF8                          # media
    struct.pack_into("<H", bs, 22, 0)        # FATSz16 (0 for FAT32)
    struct.pack_into("<H", bs, 24, 32)       # sectors per track
    struct.pack_into("<H", bs, 26, 64)       # heads
    struct.pack_into("<I", bs, 28, 0)        # hidden sectors
    struct.pack_into("<I", bs, 32, TOTAL_SEC)
    struct.pack_into("<I", bs, 36, FATSZ)
    struct.pack_into("<H", bs, 40, 0)        # ext flags
    struct.pack_into("<H", bs, 42, 0)        # fs version
    struct.pack_into("<I", bs, 44, ROOT_CLUS)
    struct.pack_into("<H", bs, 48, 1)        # FSInfo sector
    struct.pack_into("<H", bs, 50, 6)        # backup boot sector
    bs[64]    = 0x80                          # drive number
    bs[66]    = 0x29                          # extended boot signature
    struct.pack_into("<I", bs, 67, 0x12345678)
    bs[71:82] = b"AURORA DISK"
    bs[82:90] = b"FAT32   "
    bs[510]   = 0x55
    bs[511]   = 0xAA

    # ---- compute layout ----
    data_start = RSVD + NUM_FATS * FATSZ                 # sector of cluster 2
    file_first_cluster = 3
    file_clusters = max(1, (len(payload) + BPS * SPC - 1) // (BPS * SPC))

    # ---- FAT ----
    fat = bytearray(FATSZ * BPS)
    def set_fat(cluster, value):
        struct.pack_into("<I", fat, cluster * 4, value & 0x0FFFFFFF)

    set_fat(0, 0x0FFFFFF8)
    set_fat(1, FAT_EOC)
    set_fat(ROOT_CLUS, FAT_EOC)                          # root dir: one cluster
    for i in range(file_clusters):
        c = file_first_cluster + i
        set_fat(c, FAT_EOC if i == file_clusters - 1 else c + 1)

    for n in range(NUM_FATS):
        off = (RSVD + n * FATSZ) * BPS
        img[off:off + len(fat)] = fat

    # ---- root directory (cluster 2) ----
    root_off = data_start * BPS
    entry = bytearray(32)
    entry[0:11] = dos_name(dosname)
    entry[11]   = 0x20                                   # archive
    struct.pack_into("<H", entry, 20, (file_first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", entry, 26, file_first_cluster & 0xFFFF)
    struct.pack_into("<I", entry, 28, len(payload))
    img[root_off:root_off + 32] = entry

    # ---- file data ----
    file_off = (data_start + (file_first_cluster - ROOT_CLUS) * SPC) * BPS
    img[file_off:file_off + len(payload)] = payload

    with open(out_path, "wb") as f:
        f.write(img)

    sys.stderr.write(
        f"mkfat32: {out_path} ({TOTAL_SEC*BPS} bytes), "
        f"{dosname} -> cluster {file_first_cluster}, {len(payload)} bytes\n")


if __name__ == "__main__":
    main()
