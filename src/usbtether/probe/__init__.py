"""Platform-specific USB discovery."""

from __future__ import annotations

import sys

from ..errors import UnsupportedPlatformError
from .base import DeviceProbe
from .memory import InMemoryProbe

__all__ = ["DeviceProbe", "InMemoryProbe", "default_probe"]


def default_probe() -> DeviceProbe:
    """Return the probe for the current platform (Windows, or experimental Linux)."""
    if sys.platform == "win32":
        from .windows import WindowsProbe

        return WindowsProbe()
    if sys.platform.startswith("linux"):
        from .linux import LinuxProbe

        return LinuxProbe()
    raise UnsupportedPlatformError(
        f"usbtether has no USB probe for platform {sys.platform!r} (supported: Windows, Linux)"
    )
