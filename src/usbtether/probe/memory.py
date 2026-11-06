"""In-memory probe for tests, documentation and development.

It does not talk to any hardware, so it provides **no security**. It exists so that the
rest of the library can be exercised on any platform and in CI.
"""

from __future__ import annotations

from ..device import UsbDevice
from .base import DeviceProbe


class InMemoryProbe(DeviceProbe):
    def __init__(self, devices: list[UsbDevice] | None = None) -> None:
        self._devices: list[UsbDevice] = list(devices or [])

    def add(self, device: UsbDevice) -> None:
        self._devices.append(device)

    def remove(self, device: UsbDevice) -> None:
        self._devices.remove(device)

    def clear(self) -> None:
        self._devices.clear()

    def list_devices(self) -> list[UsbDevice]:
        return list(self._devices)
