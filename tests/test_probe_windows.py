import copy
import json

import pytest

from usbtether.errors import ProbeError
from usbtether.probe.windows import POWERSHELL_SCRIPT, parse_probe_json

SINGLE = json.dumps(
    [
        {
            "DiskPnpId": (
                "USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\\4C530001230101117333&0"
            ),
            "Model": "SanDisk Cruzer Blade USB Device",
            "Size": "31004098560",
            "UsbInstanceId": "USB\\VID_0781&PID_5567\\4C530001230101117333",
            "Volumes": {
                "DeviceID": "E:",
                "VolumeName": "STICK",
                "VolumeSerialNumber": "1A2B3C4D",
                "FileSystem": "exFAT",
                "Size": 31003000000,
            },
        }
    ]
)


def test_parses_single_device_with_collapsed_volume_object():
    (device,) = parse_probe_json(SINGLE)
    assert (device.vendor_id, device.product_id) == ("0781", "5567")
    assert device.serial == "4C530001230101117333"
    assert device.is_bindable
    assert device.capacity == 31_004_098_560
    (volume,) = device.volumes
    assert volume.mount_point == "E:\\"
    assert volume.volume_serial == "1A2B3C4D"
    assert volume.filesystem == "exFAT"
    assert device.volume_for("e:") is volume


def test_device_without_serial_is_reported_but_not_bindable():
    text = json.dumps(
        [
            {
                "Model": "Generic Flash Disk",
                "UsbInstanceId": "USB\\VID_058F&PID_6387\\6&1a2b3c4d&0&2",
                "Volumes": [],
            }
        ]
    )
    (device,) = parse_probe_json(text)
    assert not device.is_bindable
    assert device.volumes == ()


def test_composite_interface_nodes_are_skipped():
    text = json.dumps(
        [{"UsbInstanceId": "USB\\VID_0781&PID_5567&MI_00\\7&abc&0&0000", "Volumes": []}]
    )
    assert parse_probe_json(text) == []


def test_empty_and_null_outputs():
    assert parse_probe_json("") == []
    assert parse_probe_json("[]") == []
    assert parse_probe_json("null") == []


def test_multiple_devices():
    first = json.loads(SINGLE)[0]
    entries = [first, copy.deepcopy(first)]
    entries[1]["UsbInstanceId"] = "USB\\VID_0951&PID_1666\\0019E06B1234AB"
    devices = parse_probe_json(json.dumps(entries))
    assert [d.vendor_id for d in devices] == ["0781", "0951"]


def test_invalid_json_raises_probe_error():
    with pytest.raises(ProbeError):
        parse_probe_json("not json")


def test_script_is_read_only():
    """The script must only query. Guard against someone adding mutating cmdlets."""
    for verb in (
        "Set-",
        "Remove-",
        "New-Item",
        "Format-Volume",
        "Clear-",
        "Out-File",
        "Add-Content",
    ):
        assert verb not in POWERSHELL_SCRIPT
