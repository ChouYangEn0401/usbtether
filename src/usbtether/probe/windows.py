"""Windows USB discovery through PowerShell and CIM.

No third-party packages are needed. A PowerShell script walks, for every physical disk,
up the PnP device tree until it reaches the ``USB\\VID_xxxx&PID_xxxx\\<serial>`` node. That
node carries the numbers the USB device itself reports. Walking the tree (instead of
filtering on ``InterfaceType == 'USB'``) also covers UASP drives, which Windows reports as
SCSI disks.

The script is passed with ``-EncodedCommand`` so no shell quoting is involved. Parsing is
kept in :func:`parse_probe_json` so it can be tested without Windows.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from typing import Any

from ..device import UsbDevice, Volume
from ..errors import ProbeError
from .base import DeviceProbe

_USB_INSTANCE = re.compile(
    r"^USB\\VID_(?P<vid>[0-9A-Fa-f]{4})&PID_(?P<pid>[0-9A-Fa-f]{4})\\(?P<serial>.+)$"
)

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Get-UsbAncestor([string]$InstanceId) {
    $current = $InstanceId
    for ($i = 0; $i -lt 8; $i++) {
        $prop = Get-PnpDeviceProperty -InstanceId $current -KeyName 'DEVPKEY_Device_Parent' `
            -ErrorAction SilentlyContinue
        if (-not $prop -or -not $prop.Data) { return $null }
        $current = [string]$prop.Data
        if ($current -match '^USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\') { return $current }
    }
    return $null
}

$result = @()
foreach ($disk in @(Get-CimInstance -ClassName Win32_DiskDrive)) {
    $usb = Get-UsbAncestor $disk.PNPDeviceID
    if (-not $usb) { continue }
    $volumes = @()
    foreach ($part in @(Get-CimAssociatedInstance -InputObject $disk `
            -ResultClassName Win32_DiskPartition)) {
        foreach ($ld in @(Get-CimAssociatedInstance -InputObject $part `
                -ResultClassName Win32_LogicalDisk)) {
            $volumes += [pscustomobject]@{
                DeviceID           = $ld.DeviceID
                VolumeName         = $ld.VolumeName
                VolumeSerialNumber = $ld.VolumeSerialNumber
                FileSystem         = $ld.FileSystem
                Size               = $ld.Size
            }
        }
    }
    $result += [pscustomobject]@{
        DiskPnpId     = $disk.PNPDeviceID
        Model         = $disk.Model
        Size          = $disk.Size
        UsbInstanceId = $usb
        Volumes       = $volumes
    }
}
ConvertTo-Json -InputObject @($result) -Depth 5 -Compress
"""


def _as_list(value: Any) -> list[Any]:
    """PowerShell collapses one-element arrays; accept null, a dict, or a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _opt_int(value: Any) -> int | None:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_probe_json(text: str) -> list[UsbDevice]:
    """Turn the script's JSON output into :class:`UsbDevice` objects."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"PowerShell returned invalid JSON: {exc}") from exc

    devices: list[UsbDevice] = []
    for entry in _as_list(data):
        if not isinstance(entry, dict):
            continue
        match = _USB_INSTANCE.match(str(entry.get("UsbInstanceId") or ""))
        if match is None:
            continue
        volumes: list[Volume] = []
        for vol in _as_list(entry.get("Volumes")):
            if not isinstance(vol, dict):
                continue
            letter = _opt_str(vol.get("DeviceID"))
            volumes.append(
                Volume(
                    mount_point=f"{letter}\\" if letter else None,
                    volume_serial=_opt_str(vol.get("VolumeSerialNumber")),
                    filesystem=_opt_str(vol.get("FileSystem")),
                    capacity=_opt_int(vol.get("Size")),
                    label=_opt_str(vol.get("VolumeName")),
                )
            )
        devices.append(
            UsbDevice(
                vendor_id=match["vid"],
                product_id=match["pid"],
                serial=match["serial"],
                product=_opt_str(entry.get("Model")),
                instance_id=_opt_str(entry.get("UsbInstanceId")),
                capacity=_opt_int(entry.get("Size")),
                volumes=tuple(volumes),
            )
        )
    return devices


class WindowsProbe(DeviceProbe):
    """Reads attached USB drives via ``powershell.exe`` (read-only)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def list_devices(self) -> list[UsbDevice]:
        encoded = base64.b64encode(POWERSHELL_SCRIPT.encode("utf-16-le")).decode("ascii")
        command = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                timeout=self._timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeError(f"could not run PowerShell: {exc}") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ProbeError(f"PowerShell exited with {completed.returncode}: {stderr}")
        return parse_probe_json(completed.stdout.decode("utf-8-sig", errors="replace"))
