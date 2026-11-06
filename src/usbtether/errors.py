"""Exception hierarchy. Everything raised on purpose derives from :class:`UsbTetherError`."""

from __future__ import annotations


class UsbTetherError(Exception):
    """Base class for all usbtether errors."""


class ProbeError(UsbTetherError):
    """The operating system could not be queried for USB devices."""


class UnsupportedPlatformError(ProbeError):
    """No device probe exists for this operating system."""


class DeviceNotFoundError(UsbTetherError):
    """The requested USB device or mount point was not found."""


class UnsupportedDeviceError(UsbTetherError):
    """The USB device cannot be bound (for example it reports no real serial number)."""


class TokenError(UsbTetherError):
    """The on-drive token is missing, corrupt, locked or inconsistent."""


class AlreadyEnrolledError(UsbTetherError):
    """The drive (or its hardware identity) is already enrolled."""


class RegistryError(UsbTetherError):
    """The host-side registry could not be read or written."""


class ProtocolError(UsbTetherError):
    """A protocol message was malformed."""


class AuthorizationError(UsbTetherError):
    """A session or capability check failed. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        super().__init__(message or reason)
        self.reason = reason


class TokenLockedError(TokenError):
    """The private key is passphrase-protected and no (or a wrong) passphrase was supplied."""


class AmbiguousDeviceError(UsbTetherError):
    """More than one enrolled drive is present and none was selected."""
