#!/usr/bin/env python3
"""Convert a binary PPM (P6) to PNG using only the standard library.

Usage: ppm2png.py <in.ppm> <out.png>
"""
import sys
import zlib
import struct


def read_ppm(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:2] == b"P6", "not a P6 PPM"
    # parse the (whitespace-separated) header: magic, width, height, maxval
    idx = 2
    fields = []
    while len(fields) < 3:
        while idx < len(data) and data[idx] in b" \t\n\r":
            idx += 1
        if data[idx:idx + 1] == b"#":          # comment line
            while idx < len(data) and data[idx] not in b"\n":
                idx += 1
            continue
        start = idx
        while idx < len(data) and data[idx] not in b" \t\n\r":
            idx += 1
        fields.append(int(data[start:idx]))
    idx += 1                                    # single whitespace after maxval
    w, h, _ = fields
    return w, h, data[idx:idx + w * h * 3]


def chunk(typ, payload):
    return (struct.pack(">I", len(payload)) + typ + payload +
            struct.pack(">I", zlib.crc32(typ + payload) & 0xffffffff))


def main():
    src, dst = sys.argv[1], sys.argv[2]
    w, h, rgb = read_ppm(src)
    rows = bytearray()
    stride = w * 3
    for y in range(h):
        rows.append(0)                          # filter: none
        rows += rgb[y * stride:(y + 1) * stride]
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    png += chunk(b"IEND", b"")
    with open(dst, "wb") as f:
        f.write(png)
    sys.stderr.write(f"ppm2png: wrote {dst} ({w}x{h})\n")


if __name__ == "__main__":
    main()
