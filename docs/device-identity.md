# Device identity

usbtether binds a token to the drive's **USB device descriptor**: vendor id (VID), product id
(PID) and serial number. This page explains how those values are obtained and when they are
good enough.

## Where the values come from

### Windows

`usbtether.probe.windows` runs a read-only PowerShell script (passed with
`-EncodedCommand`; nothing is installed or modified):

1. For each `Win32_DiskDrive`, read its PnP instance id.
2. Walk **up** the device tree with `Get-PnpDeviceProperty DEVPKEY_Device_Parent` (at most 8
   levels) until the instance id matches `USB\VID_xxxx&PID_xxxx\<serial>`.
3. That node's last path segment is the serial the device itself reported. VID and PID come
   from the same node.
4. Follow `Win32_DiskDriveToDiskPartition` and `Win32_LogicalDiskToPartition` to find drive
   letters, volume serial numbers, file systems and sizes.

Walking the tree, rather than filtering on `InterfaceType = 'USB'`, also covers **UASP**
drives, which Windows reports as SCSI disks. Composite-device interface nodes
(`...&MI_00\...`) are skipped, because their last segment is a generated id; the walk
continues to the parent device node.

The drive letter is *never* part of the identity.

### Linux (experimental)

`usbtether.probe.linux` reads `idVendor`, `idProduct` and `serial` from the sysfs USB node
that owns each block device, and mount points from `/proc/mounts`.

## Serial quality

Not every drive has a usable serial. usbtether classifies it and **refuses to enroll** anything
that is not `good`:

| Quality | Meaning | Example | Bindable |
|---|---|---|---|
| `good` | Plausibly unique per unit | `4C530001230101117333` | yes |
| `missing` | The device reports none | (empty) | no |
| `generated` | Windows synthesised an id from the port; the second character is `&` | `6&1a2b3c4d&0&2` | no |
| `suspicious` | Placeholder or obviously shared | `00000000`, `FFFFFFFF`, `0123456789ABCDEF`, shorter than 4 characters | no |

These are **heuristics**. A serial that passes can still be duplicated across units by a
careless manufacturer, and some cheap drives ship identical serials. `usbtether devices`
shows what your drive reports. Test two drives of the same model before relying on it.

## Identity versus advisory fields

| Field | Role |
|---|---|
| vendor id, product id, serial | **Identity.** Hashed into the fingerprint. All must match. |
| product name, volume serial, file system, capacity | **Advisory.** Stored and compared; a difference yields a warning only, because reformatting legitimately changes them. |

## Privacy

Serial numbers are persistent identifiers. They are stored in the host registry and in the
signed device report, and printed by `usbtether devices`. When you share output in an issue,
use `usbtether devices --json --redact`.

## Contributing device data

The Windows probe has been written against documented Windows behaviour and tested against
recorded fixtures, not yet against a broad set of real drives. If a drive is mis-detected,
open an issue with the *redacted* output of `usbtether devices --json --redact` and the
drive's connection type (USB 2/3, hub, adapter).
