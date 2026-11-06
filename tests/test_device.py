import pytest

from usbtether.device import (
    DeviceReport,
    SerialQuality,
    advisory_warnings,
    classify_serial,
    device_fingerprint,
    normalize_mount,
)
from usbtether.errors import UnsupportedDeviceError

from .conftest import make_device


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA00112233445566", SerialQuality.GOOD),
        ("  aa00112233445566 ", SerialQuality.GOOD),
        (None, SerialQuality.MISSING),
        ("", SerialQuality.MISSING),
        ("   ", SerialQuality.MISSING),
        ("5&2b9a8c7&0&2", SerialQuality.GENERATED),
        ("6&1A2B3C4D&0", SerialQuality.GENERATED),
        ("000000000000", SerialQuality.SUSPICIOUS),
        ("FFFFFFFF", SerialQuality.SUSPICIOUS),
        ("123", SerialQuality.SUSPICIOUS),
        ("0123456789abcdef", SerialQuality.SUSPICIOUS),
        ("Unknown", SerialQuality.SUSPICIOUS),
    ],
)
def test_classify_serial(raw, expected):
    assert classify_serial(raw) is expected


def test_fingerprint_is_stable_and_case_insensitive():
    a = device_fingerprint("0781", "5567", "aa00112233445566")
    b = device_fingerprint("0781", "5567", "AA00112233445566 ")
    assert a == b
    assert len(a) == 64


def test_fingerprint_depends_on_every_identity_field():
    base = device_fingerprint("0781", "5567", "AA00112233445566")
    assert base != device_fingerprint("0782", "5567", "AA00112233445566")
    assert base != device_fingerprint("0781", "5568", "AA00112233445566")
    assert base != device_fingerprint("0781", "5567", "AA00112233445567")


def test_fingerprint_ignores_volume_data():
    a = make_device(volume_serial="1111-1111", mount="E:\\")
    b = make_device(volume_serial="2222-2222", mount="F:\\")
    assert a.fingerprint == b.fingerprint


def test_unbindable_device_refuses_fingerprint():
    device = make_device(serial="5&2b9a8c7&0&2")
    assert not device.is_bindable
    with pytest.raises(UnsupportedDeviceError):
        _ = device.fingerprint


def test_ids_are_validated_and_normalised():
    assert make_device(vid="ABCD", pid="00FF").vendor_id == "abcd"
    with pytest.raises(ValueError):
        make_device(vid="xyz1")


def test_report_roundtrip():
    device = make_device(mount="E:\\")
    report = device.report()
    assert DeviceReport.from_dict(report.to_dict()) == report
    assert report.fingerprint() == device.fingerprint


def test_report_from_dict_rejects_garbage():
    with pytest.raises(ValueError):
        DeviceReport.from_dict({"vendor_id": "0781"})


def test_advisory_warnings_only_on_real_differences():
    registered = make_device(mount="E:\\", volume_serial="1111-1111").report().to_dict()
    same = make_device(mount="F:\\", volume_serial="1111-1111").report()
    changed = make_device(mount="F:\\", volume_serial="9999-9999").report()
    assert advisory_warnings(registered, same) == []
    assert advisory_warnings(registered, changed) == ["volume_serial_changed"]


def test_normalize_mount_variants():
    assert normalize_mount("E:") == normalize_mount("E:\\")


def test_normalize_mount_is_case_insensitive_for_drive_letters():
    assert normalize_mount("e:") == normalize_mount("E:\\")
    assert normalize_mount("e:\\") == normalize_mount("E:\\")
