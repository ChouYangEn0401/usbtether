"""Draw src/usbtether/usbtether.ico (a padlock on a dark tile) with the standard library only.

Run once after changing the design: ``python packaging/make_icon.py``. The .ico is committed.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

BG = (14, 23, 39)
EDGE = (35, 126, 145)
CYAN = (103, 232, 249)
SIZES = (16, 24, 32, 48, 64, 128, 256)


def _rounded_box(x: float, y: float, cx: float, cy: float, hw: float, hh: float, r: float) -> float:
    """Signed distance to a rounded rectangle (negative inside)."""
    dx, dy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
    out = math.hypot(max(dx, 0.0), max(dy, 0.0))
    return out + min(max(dx, dy), 0.0) - r


def _pixel(u: float, v: float) -> tuple[float, float, float, float]:
    """Colour at (u, v) in [0, 1]^2 as RGBA floats."""
    tile = _rounded_box(u, v, 0.5, 0.5, 0.47, 0.47, 0.2)
    if tile > 0:
        return (0, 0, 0, 0)
    col = EDGE if tile > -0.035 else BG
    # padlock body
    body = _rounded_box(u, v, 0.5, 0.62, 0.22, 0.17, 0.05)
    # shackle: a ring segment above the body
    ring = abs(math.hypot(u - 0.5, v - 0.42) - 0.14) - 0.045
    shackle = ring if v < 0.5 else 1.0
    keyhole = math.hypot(u - 0.5, v - 0.6) - 0.045
    slot = _rounded_box(u, v, 0.5, 0.67, 0.018, 0.05, 0.01)
    if (body < 0 or shackle < 0) and not (keyhole < 0 or slot < 0):
        col = CYAN
    return (*col, 255)


def render(size: int) -> bytes:
    ss = 4  # supersampling for smooth edges
    rows = []
    for y in range(size):
        row = bytearray([0])  # PNG filter: none
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(ss):
                for sx in range(ss):
                    r, g, b, a = _pixel((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            n = ss * ss
            alpha = acc[3] / n
            rgb = [int(c / acc[3]) if acc[3] else 0 for c in acc[:3]]
            row += bytes([*rgb, int(alpha)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main() -> None:
    images = [render(s) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for size, data in zip(SIZES, images, strict=True):
        dim = 0 if size == 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    out = Path(__file__).resolve().parents[1] / "src" / "usbtether" / "usbtether.ico"
    out.write_bytes(header + entries + b"".join(images))
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
