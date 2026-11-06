"""Abstract device probe: the only place that talks to the operating system."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from ..device import UsbDevice, Volume
from ..errors import DeviceNotFoundError


class DeviceProbe(ABC):
    """Enumerates attached USB mass-storage devices.

    Implementations must be side-effect free: they only *read* system state.
    """

    @abstractmethod
    def list_devices(self) -> list[UsbDevice]:
        """Return every attached USB mass-storage device, mounted or not."""

    def find_by_mount(self, mount: str | os.PathLike[str]) -> tuple[UsbDevice, Volume]:
        """Locate the device and volume mounted at ``mount`` (``E:``, ``E:\\``, ``/media/x``)."""
        for device in self.list_devices():
            volume = device.volume_for(os.fspath(mount))
            if volume is not None:
                return device, volume
        raise DeviceNotFoundError(f"no USB drive is mounted at {os.fspath(mount)!r}")

    def find_by_fingerprint(self, fingerprint: str) -> UsbDevice | None:
        for device in self.list_devices():
            if device.is_bindable and device.fingerprint == fingerprint:
                return device
        return None
