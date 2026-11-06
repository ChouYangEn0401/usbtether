import os

from usbtether.probe.linux import LinuxProbe


def _build_sysfs(root, *, serial: str | None):
    usb = root / "devices/pci0000:00/usb1/1-2"
    iface = usb / "1-2:1.0/host6/target6:0:0/6:0:0:0/block/sdb"
    (iface / "sdb1").mkdir(parents=True)
    (usb / "idVendor").write_text("0781\n")
    (usb / "idProduct").write_text("5567\n")
    (usb / "product").write_text("Cruzer Blade\n")
    if serial is not None:
        (usb / "serial").write_text(serial + "\n")
    (iface / "size").write_text("62914560\n")  # 512-byte sectors -> 32.2 GB
    (root / "block").mkdir()
    os.symlink(iface, root / "block/sdb")
    # A non-USB disk that must be ignored.
    sata = root / "devices/pci0000:00/ata1/host0/block/sda"
    sata.mkdir(parents=True)
    os.symlink(sata, root / "block/sda")


def test_lists_usb_disk_with_mount(tmp_path):
    sysfs = tmp_path / "sys"
    _build_sysfs(sysfs, serial="4C530001230101117333")
    mounts = tmp_path / "mounts"
    mounts.write_text("/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /media/user/MY\\040STICK vfat rw 0 0\n")
    (device,) = LinuxProbe(sysfs, mounts).list_devices()
    assert (device.vendor_id, device.product_id) == ("0781", "5567")
    assert device.serial == "4C530001230101117333"
    assert device.product == "Cruzer Blade"
    assert device.capacity == 62914560 * 512
    (volume,) = device.volumes
    assert volume.mount_point == "/media/user/MY STICK"
    assert volume.filesystem == "vfat"


def test_missing_serial_is_reported_as_unbindable(tmp_path):
    sysfs = tmp_path / "sys"
    _build_sysfs(sysfs, serial=None)
    (device,) = LinuxProbe(sysfs, tmp_path / "nomounts").list_devices()
    assert device.serial is None
    assert not device.is_bindable


def test_no_sysfs_means_no_devices(tmp_path):
    assert LinuxProbe(tmp_path / "missing", tmp_path / "m").list_devices() == []
