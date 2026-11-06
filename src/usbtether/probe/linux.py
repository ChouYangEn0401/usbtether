"""Experimental Linux USB discovery from sysfs and ``/proc/mounts``.

Linux support exists so the project can be developed and tested outside Windows. It reads
``idVendor``/``idProduct``/``serial`` from the USB device node that owns each block device.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..device import UsbDevice, Volume
from .base import DeviceProbe

_OCTAL = re.compile(r"\\([0-7]{3})")


def _read(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return text or None


def _unescape(field: str) -> str:
    """``/proc/mounts`` escapes space, tab, newline and backslash as octal."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), field)


class LinuxProbe(DeviceProbe):
    def __init__(
        self,
        sysfs: str | os.PathLike[str] = "/sys",
        mounts: str | os.PathLike[str] = "/proc/mounts",
    ) -> None:
        self._sysfs = Path(sysfs)
        self._mounts = Path(mounts)

    def _mount_table(self) -> dict[str, tuple[str, str]]:
        table: dict[str, tuple[str, str]] = {}
        text = _read(self._mounts) or ""
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("/dev/"):
                table[_unescape(parts[0])] = (_unescape(parts[1]), parts[2])
        return table

    def list_devices(self) -> list[UsbDevice]:
        block_root = self._sysfs / "block"
        if not block_root.is_dir():
            return []
        mounts = self._mount_table()
        devices: list[UsbDevice] = []
        for entry in sorted(block_root.iterdir()):
            real = entry.resolve()
            usb_node = next(
                (
                    p
                    for p in [real, *real.parents]
                    if (p / "idVendor").is_file() and (p / "idProduct").is_file()
                ),
                None,
            )
            if usb_node is None:
                continue
            vid, pid = _read(usb_node / "idVendor"), _read(usb_node / "idProduct")
            if not vid or not pid:
                continue
            size = _read(real / "size")
            capacity = int(size) * 512 if size and size.isdigit() else None
            volumes: list[Volume] = []
            partitions = sorted(
                child.name for child in real.iterdir() if child.name.startswith(entry.name)
            )
            nodes = [entry.name, *partitions]
            for name in nodes:
                mount = mounts.get(f"/dev/{name}")
                if mount:
                    volumes.append(
                        Volume(mount_point=mount[0], filesystem=mount[1], capacity=capacity)
                    )
            devices.append(
                UsbDevice(
                    vendor_id=vid,
                    product_id=pid,
                    serial=_read(usb_node / "serial"),
                    product=_read(usb_node / "product"),
                    instance_id=str(usb_node.name),
                    capacity=capacity,
                    volumes=tuple(volumes),
                )
            )
        return devices
