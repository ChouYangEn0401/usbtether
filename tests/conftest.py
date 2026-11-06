from __future__ import annotations

import pytest

from usbtether.device import UsbDevice, Volume
from usbtether.probe.memory import InMemoryProbe


def make_device(
    serial: str | None = "AA00112233445566",
    *,
    vid: str = "0781",
    pid: str = "5567",
    mount: str | None = None,
    volume_serial: str | None = "1A2B-3C4D",
) -> UsbDevice:
    volumes = (
        (
            Volume(
                mount_point=mount,
                volume_serial=volume_serial,
                filesystem="exFAT",
                capacity=32_000_000_000,
            ),
        )
        if mount
        else ()
    )
    return UsbDevice(
        vendor_id=vid,
        product_id=pid,
        serial=serial,
        product="Cruzer Blade",
        capacity=32_000_000_000,
        volumes=volumes,
    )


@pytest.fixture
def stick(tmp_path):
    """A bindable drive whose 'mount point' is a real temporary directory."""
    mount = tmp_path / "stick"
    mount.mkdir()
    return make_device(mount=str(mount)), mount


@pytest.fixture
def probe(stick):
    device, _ = stick
    return InMemoryProbe([device])
