#!/usr/bin/env python3
"""Build a minimal FAT32 disk image with one or more files in the root dir.

Usage: mkfat32.py <out.img> <DOSNAME1> <src1> [<DOSNAME2> <src2> ...]
Example: mkfat32.py disk.img INIT.ELF user/init.elf CHILD.ELF user/child.elf
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
    base, _, ext = name.partition(".")
    return (base.upper()[:8].ljust(8) + ext.upper()[:3].ljust(3)).encode("ascii")


def main():
    if len(sys.argv) < 4 or (len(sys.argv) - 2) % 2 != 0:
        sys.stderr.write("usage: mkfat32.py <out.img> <NAME> <src> [<NAME> <src> ...]\n")
        sys.exit(1)

    out_path = sys.argv[1]
    files = []
    for i in range(2, len(sys.argv), 2):
        with open(sys.argv[i + 1], "rb") as f:
            files.append((sys.argv[i], f.read()))

    img = bytearray(TOTAL_SEC * BPS)

    # ---- boot sector / BPB ----
    bs = img
    bs[0:3]   = b"\xEB\x58\x90"
    bs[3:11]  = b"MSWIN4.1"
    struct.pack_into("<H", bs, 11, BPS)
    bs[13]    = SPC
    struct.pack_into("<H", bs, 14, RSVD)
    bs[16]    = NUM_FATS
    struct.pack_into("<H", bs, 17, 0)
    struct.pack_into("<H", bs, 19, 0)
    bs[21]    = 0xF8
    struct.pack_into("<H", bs, 22, 0)
    struct.pack_into("<H", bs, 24, 32)
    struct.pack_into("<H", bs, 26, 64)
    struct.pack_into("<I", bs, 28, 0)
    struct.pack_into("<I", bs, 32, TOTAL_SEC)
    struct.pack_into("<I", bs, 36, FATSZ)
    struct.pack_into("<H", bs, 40, 0)
    struct.pack_into("<H", bs, 42, 0)
    struct.pack_into("<I", bs, 44, ROOT_CLUS)
    struct.pack_into("<H", bs, 48, 1)
    struct.pack_into("<H", bs, 50, 6)
    bs[64]    = 0x80
    bs[66]    = 0x29
    struct.pack_into("<I", bs, 67, 0x12345678)
    bs[71:82] = b"AURORA DISK"
    bs[82:90] = b"FAT32   "
    bs[510]   = 0x55
    bs[511]   = 0xAA

    data_start = RSVD + NUM_FATS * FATSZ
    clus_bytes = BPS * SPC

    # ---- assign clusters: root dir at 2, files from 3 onward ----
    fat = bytearray(FATSZ * BPS)
    def set_fat(cluster, value):
        struct.pack_into("<I", fat, cluster * 4, value & 0x0FFFFFFF)

    set_fat(0, 0x0FFFFFF8)
    set_fat(1, FAT_EOC)
    set_fat(ROOT_CLUS, FAT_EOC)

    next_cluster = 3
    placements = []     # (name, first_cluster, data)
    for name, data in files:
        nclus = max(1, (len(data) + clus_bytes - 1) // clus_bytes)
        first = next_cluster
        for i in range(nclus):
            c = first + i
            set_fat(c, FAT_EOC if i == nclus - 1 else c + 1)
        placements.append((name, first, data))
        next_cluster += nclus

    for n in range(NUM_FATS):
        off = (RSVD + n * FATSZ) * BPS
        img[off:off + len(fat)] = fat

    # ---- root directory entries + file data ----
    root_off = data_start * BPS
    for idx, (name, first, data) in enumerate(placements):
        entry = bytearray(32)
        entry[0:11] = dos_name(name)
        entry[11]   = 0x20
        struct.pack_into("<H", entry, 20, (first >> 16) & 0xFFFF)
        struct.pack_into("<H", entry, 26, first & 0xFFFF)
        struct.pack_into("<I", entry, 28, len(data))
        eo = root_off + idx * 32
        img[eo:eo + 32] = entry

        fo = (data_start + (first - ROOT_CLUS) * SPC) * BPS
        img[fo:fo + len(data)] = data

    with open(out_path, "wb") as f:
        f.write(img)

    names = ", ".join(f"{n}@{c}" for n, c, _ in placements)
    sys.stderr.write(f"mkfat32: {out_path} ({TOTAL_SEC*BPS} bytes): {names}\n")


if __name__ == "__main__":
    main()
