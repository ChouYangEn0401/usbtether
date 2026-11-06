"""USB device model, identity-quality rules and fingerprints.

The *identity* of a drive is the triple ``(vendor id, product id, serial number)`` as
reported by the USB device descriptor. Volume-level data (volume serial, file system,
capacity) lives in the *advisory* fields: it is recorded and compared, but a mismatch only
produces a warning, because it legitimately changes when a drive is reformatted.

See ``docs/device-identity.md`` for the reasoning and the limits of this approach.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ._canonical import canonical_json
from .errors import UnsupportedDeviceError

FINGERPRINT_SCHEME = "usbtether-device-v1"

_HEX4 = re.compile(r"^[0-9a-f]{4}$")

# Serial numbers that are shipped by many unrelated units, or that mean "nothing".
_PLACEHOLDER_SERIALS = frozenset(
    {
        "0123456789ABCDEF",
        "ABCDEF0123456789",
        "1234567890ABCDEF",
        "1234567890",
        "123456789",
        "12345678",
        "NONE",
        "NULL",
        "N/A",
        "UNKNOWN",
        "SERIAL",
        "SERIALNUMBER",
        "DEFAULTSTRING",
    }
)

ADVISORY_FIELDS = ("product", "volume_serial", "filesystem", "capacity")


class SerialQuality(str, Enum):
    """How much a reported serial number can be trusted as a per-unit identifier."""

    GOOD = "good"
    MISSING = "missing"
    GENERATED = "generated"  # synthesised by the OS from the port, not by the device
    SUSPICIOUS = "suspicious"  # placeholder or obviously non-unique value


def normalize_serial(raw: str) -> str:
    """Canonical form of a serial number used for comparison and hashing."""
    return raw.strip().upper()


def classify_serial(raw: str | None) -> SerialQuality:
    """Classify a raw serial number.

    The rules are heuristics and intentionally conservative: when in doubt, a serial is
    *not* ``GOOD``, and the device is refused rather than silently downgraded.
    """
    if raw is None or not raw.strip():
        return SerialQuality.MISSING
    value = normalize_serial(raw)
    # Windows builds an instance id such as ``5&2b9a8c7&0&2`` for devices without a serial;
    # the second character is always '&'. Such ids depend on the port, not on the drive.
    if len(value) >= 2 and value[1] == "&":
        return SerialQuality.GENERATED
    if len(value) < 4 or len(set(value)) == 1 or value in _PLACEHOLDER_SERIALS:
        return SerialQuality.SUSPICIOUS
    return SerialQuality.GOOD


def normalize_mount(mount: str | os.PathLike[str]) -> str:
    """Normalise a mount point (``E:``, ``e:\\``, ``/media/x/``) for comparison."""
    text = os.fspath(mount)
    if re.fullmatch(r"[A-Za-z]:", text):
        text += "\\"
    if re.match(r"[A-Za-z]:[\\/]", text):
        text = text[0].upper() + text[1:]  # drive letters are case-insensitive on every platform
    return os.path.normcase(os.path.normpath(text))


def device_fingerprint(vendor_id: str, product_id: str, serial: str) -> str:
    """SHA-256 over the canonical identity triple. Not a secret, only a stable identifier."""
    payload = {
        "scheme": FINGERPRINT_SCHEME,
        "vid": vendor_id.strip().lower(),
        "pid": product_id.strip().lower(),
        "serial": normalize_serial(serial),
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class Volume:
    """A mounted file system on a USB drive."""

    mount_point: str | None
    volume_serial: str | None = None
    filesystem: str | None = None
    capacity: int | None = None
    label: str | None = None


@dataclass(frozen=True)
class UsbDevice:
    """A physical USB mass-storage device as seen by the operating system."""

    vendor_id: str
    product_id: str
    serial: str | None
    product: str | None = None
    instance_id: str | None = None
    capacity: int | None = None
    volumes: tuple[Volume, ...] = ()

    def __post_init__(self) -> None:
        vid = self.vendor_id.strip().lower()
        pid = self.product_id.strip().lower()
        if not _HEX4.match(vid) or not _HEX4.match(pid):
            raise ValueError(f"vendor/product id must be 4 hex digits, got {vid!r}/{pid!r}")
        object.__setattr__(self, "vendor_id", vid)
        object.__setattr__(self, "product_id", pid)

    @property
    def serial_quality(self) -> SerialQuality:
        return classify_serial(self.serial)

    @property
    def is_bindable(self) -> bool:
        """True when the device has a serial good enough to bind a token to."""
        return self.serial_quality is SerialQuality.GOOD

    @property
    def fingerprint(self) -> str:
        if not self.is_bindable or self.serial is None:
            raise UnsupportedDeviceError(
                f"device {self.vendor_id}:{self.product_id} has no usable serial "
                f"(quality: {self.serial_quality.value})"
            )
        return device_fingerprint(self.vendor_id, self.product_id, self.serial)

    def volume_for(self, mount_point: str) -> Volume | None:
        wanted = normalize_mount(mount_point)
        for volume in self.volumes:
            if volume.mount_point and normalize_mount(volume.mount_point) == wanted:
                return volume
        return None

    def report(self, volume: Volume | None = None) -> DeviceReport:
        """Snapshot of this device (and optionally one volume) for protocol messages."""
        chosen = volume or (self.volumes[0] if self.volumes else None)
        return DeviceReport(
            vendor_id=self.vendor_id,
            product_id=self.product_id,
            serial=normalize_serial(self.serial) if self.serial else None,
            product=self.product,
            volume_serial=chosen.volume_serial if chosen else None,
            filesystem=chosen.filesystem if chosen else None,
            capacity=self.capacity,
        )


@dataclass(frozen=True)
class DeviceReport:
    """What an agent claims about the drive it is using. Signed as part of every response."""

    vendor_id: str
    product_id: str
    serial: str | None
    product: str | None = None
    volume_serial: str | None = None
    filesystem: str | None = None
    capacity: int | None = None

    @property
    def serial_quality(self) -> SerialQuality:
        return classify_serial(self.serial)

    def fingerprint(self) -> str:
        if self.serial_quality is not SerialQuality.GOOD or self.serial is None:
            raise UnsupportedDeviceError(f"serial quality is {self.serial_quality.value}")
        return device_fingerprint(self.vendor_id, self.product_id, self.serial)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial": self.serial,
            "product": self.product,
            "volume_serial": self.volume_serial,
            "filesystem": self.filesystem,
            "capacity": self.capacity,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeviceReport:
        try:
            capacity = data.get("capacity")
            return cls(
                vendor_id=str(data["vendor_id"]),
                product_id=str(data["product_id"]),
                serial=None if data["serial"] is None else str(data["serial"]),
                product=_opt_str(data.get("product")),
                volume_serial=_opt_str(data.get("volume_serial")),
                filesystem=_opt_str(data.get("filesystem")),
                capacity=None if capacity is None else int(capacity),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid device report: {exc}") from exc


def advisory_warnings(registered: Mapping[str, Any], reported: DeviceReport) -> list[str]:
    """Names of advisory fields whose value differs from the enrolled one.

    These never fail authentication: reformatting a drive changes the volume serial.
    """
    current = reported.to_dict()
    return [
        f"{name}_changed"
        for name in ADVISORY_FIELDS
        if registered.get(name) is not None
        and current.get(name) is not None
        and registered[name] != current[name]
    ]


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)
