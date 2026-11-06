import pytest

from usbtether.enrollment import enroll
from usbtether.errors import (
    AlreadyEnrolledError,
    DeviceNotFoundError,
    RegistryError,
    UnsupportedDeviceError,
    UsbTetherError,
)
from usbtether.probe.memory import InMemoryProbe
from usbtether.protocol import AuthResult, FailureReason
from usbtether.token import TOKEN_DIR, has_token, read_token

from .conftest import add_stick, make_device


def test_enroll_writes_token_and_registers_binding(stick, probe, registry):
    device, mount = stick
    result = enroll(probe, registry, mount, label="my key")
    assert has_token(mount)
    entry = registry.get(result.token.token_id)
    assert entry is not None
    assert entry.is_active
    assert entry.label == "my key"
    assert entry.fingerprint == device.fingerprint
    assert entry.public_key == read_token(mount).public_key_b64
    assert entry.device["volume_serial"] == "1A2B-3C4D"
    assert "private" not in str(entry)  # the private key never reaches the host registry


def test_drive_without_real_serial_is_refused_and_untouched(tmp_path, registry):
    probe = InMemoryProbe()
    for name, serial in [("none", None), ("generated", "6&1a2b3c4d&0&2"), ("fake", "00000000")]:
        _, mount = add_stick(tmp_path, probe, name, serial)
        with pytest.raises(UnsupportedDeviceError):
            enroll(probe, registry, mount)
        assert not (mount / TOKEN_DIR).exists()
    assert registry.entries() == []


def test_unknown_mount(probe, registry):
    with pytest.raises(DeviceNotFoundError):
        enroll(probe, registry, "/not/mounted")


def test_second_enrollment_needs_overwrite(stick, probe, registry):
    _, mount = stick
    enroll(probe, registry, mount)
    with pytest.raises(AlreadyEnrolledError):
        enroll(probe, registry, mount)
    assert len(registry.entries()) == 1


def test_wiped_drive_is_still_known_to_the_registry(stick, probe, registry):
    _, mount = stick
    enroll(probe, registry, mount)
    for f in (mount / TOKEN_DIR).iterdir():
        f.unlink()
    (mount / TOKEN_DIR).rmdir()
    with pytest.raises(AlreadyEnrolledError):
        enroll(probe, registry, mount)


def test_overwrite_revokes_the_previous_token(stick, probe, registry):
    _, mount = stick
    first = enroll(probe, registry, mount)
    second = enroll(probe, registry, mount, overwrite=True)
    assert second.revoked == (first.token.token_id,)
    assert not registry.get(first.token.token_id).is_active
    assert registry.get(second.token.token_id).is_active
    assert read_token(mount).token_id == second.token.token_id


def test_self_test_failure_rolls_everything_back(stick, probe, registry, monkeypatch):
    _, mount = stick
    monkeypatch.setattr(
        "usbtether.enrollment.Verifier.authenticate",
        lambda *a, **k: AuthResult(False, reason=FailureReason.BAD_SIGNATURE),
    )
    with pytest.raises(UsbTetherError, match="self-test"):
        enroll(probe, registry, mount)
    assert registry.entries() == []
    assert not (mount / TOKEN_DIR).exists()


def test_registry_failure_rolls_the_token_back(stick, probe, registry, monkeypatch):
    _, mount = stick

    def boom(entry):
        raise RegistryError("disk full")

    monkeypatch.setattr(registry, "add", boom)
    with pytest.raises(RegistryError):
        enroll(probe, registry, mount)
    assert not (mount / TOKEN_DIR).exists()


def test_two_different_drives_enroll_independently(tmp_path, registry):
    probe = InMemoryProbe()
    _, a = add_stick(tmp_path, probe, "a", "AA00112233445566")
    _, b = add_stick(tmp_path, probe, "b", "BB00112233445566")
    enroll(probe, registry, a)
    enroll(probe, registry, b)
    assert len(registry.entries()) == 2
    assert (
        make_device("AA00112233445566").fingerprint != make_device("BB00112233445566").fingerprint
    )
