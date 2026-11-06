"""End to end through the real LinuxProbe (against a fake sysfs) instead of InMemoryProbe."""

import os
import shutil
import sys

import pytest

from usbtether import Agent, Registry, Verifier, enroll
from usbtether.probe.linux import LinuxProbe
from usbtether.protocol import FailureReason
from usbtether.token import TOKEN_DIR

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")


def plug(sysfs, name, bus, serial):
    usb = sysfs / f"devices/pci0000:00/usb1/{bus}"
    block = usb / f"{bus}:1.0/host6/target6:0:0/6:0:0:0/block/{name}"
    (block / f"{name}1").mkdir(parents=True)
    (usb / "idVendor").write_text("0781\n")
    (usb / "idProduct").write_text("5567\n")
    (usb / "serial").write_text(serial + "\n")
    (block / "size").write_text("62914560\n")
    (sysfs / "block").mkdir(exist_ok=True)
    os.symlink(block, sysfs / "block" / name)


def test_enroll_verify_and_clone_rejection_through_linux_probe(tmp_path):
    sysfs = tmp_path / "sys"
    original, clone = tmp_path / "mnt_original", tmp_path / "mnt_clone"
    original.mkdir()
    clone.mkdir()
    plug(sysfs, "sdb", "1-2", "4C530001230101117333")
    plug(sysfs, "sdc", "1-3", "4C530009999999999999")
    mounts = tmp_path / "mounts"
    mounts.write_text(f"/dev/sdb1 {original} vfat rw 0 0\n/dev/sdc1 {clone} vfat rw 0 0\n")

    probe = LinuxProbe(sysfs, mounts)
    registry = Registry(tmp_path / "registry.json")
    result = enroll(probe, registry, original, label="e2e")
    assert result.device.serial == "4C530001230101117333"

    verifier, agent = Verifier(registry), Agent(probe)
    assert verifier.authenticate(agent, "login", original).ok

    shutil.copytree(original / TOKEN_DIR, clone / TOKEN_DIR)
    outcome = verifier.authenticate(agent, "login", clone)
    assert not outcome.ok
    assert outcome.reason is FailureReason.DEVICE_MISMATCH
