"""The library core (usbtether.core.KeyRing) with simulated drives in temporary folders."""

import shutil

import pytest

from usbtether import (
    AmbiguousDeviceError,
    DriveVerificationError,
    FileSecretStore,
    InMemoryProbe,
    KeyNotPresentError,
    KeyRevokedError,
    KeyRing,
    NotEncryptedError,
    PasswordRequiredError,
    TamperedError,
    TokenLockedError,
    UnknownKeyError,
    UnsupportedDeviceError,
    VaultError,
    WrongKeyError,
    WrongPasswordError,
)
from usbtether.core import DATA_MAGIC, MESSAGE_PREFIX
from usbtether.vault import decrypt_file, drive_key

from .conftest import add_stick, make_device


@pytest.fixture
def ring(tmp_path, probe):
    store = FileSecretStore(tmp_path / "home" / "secrets")
    return KeyRing(tmp_path / "home", probe=probe, secret_store=store)


def test_register_list_and_record_has_no_secrets(ring, stick, tmp_path):
    _, mount = stick
    key = ring.register(mount, label="desk key", remember=True)
    assert key.label == "desk key" and key.active
    assert (key.vendor_id, key.product_id) == ("0781", "5567")
    assert len(key.fingerprint) == 64
    assert "AA00112233445566" not in repr(key)  # the raw serial is not part of the record
    assert ring.keys() == [key]
    assert ring.get(key.key_id) == key
    assert (tmp_path / "home" / "registry.json").is_file()  # metadata lives in the given home


def test_default_home_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.setenv("USBTETHER_HOME", str(tmp_path / "env-home"))
    ring = KeyRing(probe=InMemoryProbe())
    assert ring.home == tmp_path / "env-home"
    assert ring.registry.path == tmp_path / "env-home" / "registry.json"


def test_drives_reports_bindable_and_registered(ring, stick, probe, tmp_path):
    _, mount = stick
    add_stick(tmp_path, probe, "cheap", "0123456789ABCDEF", pid="1111")
    probe.add(make_device("BB99887766554433", pid="2222"))  # attached but not mounted
    before = {d.product_id: d for d in ring.drives()}
    assert before["5567"].bindable and before["5567"].key_id is None
    assert not before["1111"].bindable and before["1111"].fingerprint is None
    assert before["2222"].mount_point is None
    key = ring.register(mount, remember=True)
    after = {d.product_id: d for d in ring.drives()}
    assert after["5567"].key_id == key.key_id and after["5567"].registered


def test_unbindable_drive_cannot_be_registered(ring, probe, tmp_path):
    _, mount = add_stick(tmp_path, probe, "cheap", None, pid="1111")
    with pytest.raises(UnsupportedDeviceError):
        ring.register(mount)


def test_bytes_roundtrip_and_header(ring, stick):
    _, mount = stick
    key = ring.register(mount, remember=True)
    blob = ring.encrypt(b"hello", key.key_id)
    assert blob.startswith(DATA_MAGIC) and b"hello" not in blob
    assert KeyRing.key_id_of(blob) == key.key_id
    assert ring.decrypt(blob) == b"hello"
    assert ring.decrypt(blob, key_id=key.key_id) == b"hello"
    assert ring.encrypt(b"hello", key.key_id) != blob  # fresh nonce every time


def test_message_roundtrip(ring, stick):
    _, mount = stick
    key = ring.register(mount, remember=True)
    message = ring.encrypt_message("你好 usbtether", key.key_id)
    assert message.startswith(MESSAGE_PREFIX) and message.isascii()
    assert ring.decrypt_message(message) == "你好 usbtether"
    with pytest.raises(NotEncryptedError):
        ring.decrypt_message("hello")


def test_tampering_is_detected(ring, stick):
    _, mount = stick
    key = ring.register(mount, remember=True)
    blob = bytearray(ring.encrypt(b"hello world", key.key_id))
    blob[-1] ^= 1
    with pytest.raises(TamperedError):
        ring.decrypt(bytes(blob))
    with pytest.raises(NotEncryptedError):
        ring.decrypt(b"UTD1short")
    with pytest.raises(NotEncryptedError):
        ring.decrypt(b"x" * 100)


def test_key_must_be_plugged_in(ring, stick, probe):
    device, mount = stick
    key = ring.register(mount, remember=True)
    blob = ring.encrypt(b"data", key.key_id)
    assert ring.is_present(key.key_id)
    probe.remove(device)
    assert not ring.is_present(key.key_id) and ring.present_keys() == []
    with pytest.raises(KeyNotPresentError):
        ring.decrypt(blob)
    with pytest.raises(KeyNotPresentError):
        ring.encrypt(b"data", key.key_id)
    probe.add(device)
    assert ring.decrypt(blob) == b"data"


def test_choosing_between_several_keys(ring, stick, probe, tmp_path):
    _, mount = stick
    _, mount_b = add_stick(tmp_path, probe, "second", "BB99887766554433", pid="2222")
    a = ring.register(mount, label="a", remember=True)
    b = ring.register(mount_b, label="b", remember=True)
    assert {k.key_id for k in ring.present_keys()} == {a.key_id, b.key_id}
    blob_a = ring.encrypt(b"for a", a.key_id)
    blob_b = ring.encrypt(b"for b", b.key_id)
    assert ring.decrypt(blob_a) == b"for a" and ring.decrypt(blob_b) == b"for b"
    with pytest.raises(WrongKeyError):
        ring.decrypt(blob_a, key_id=b.key_id)
    # swapping the key id in the header is caught: it is authenticated data
    forged = blob_a[:4] + blob_b[4:20] + blob_a[20:]
    with pytest.raises(TamperedError):
        ring.decrypt(forged)


def test_password_protected_key(ring, stick):
    _, mount = stick
    key = ring.register(mount, password="correct horse")
    blob = ring.encrypt(b"data", key.key_id, password="correct horse")
    with pytest.raises(PasswordRequiredError):
        ring.decrypt(blob)
    with pytest.raises(WrongPasswordError):
        ring.decrypt(blob, password="wrong")
    assert isinstance(WrongPasswordError("x"), TokenLockedError)  # old handlers still catch it
    assert ring.decrypt(blob, password=b"correct horse") == b"data"
    asked: list[int] = []

    def ask() -> bytes:
        asked.append(1)
        return b"correct horse"

    assert ring.decrypt(blob, password=ask) == b"data" and asked


def test_remembered_key_needs_this_computer(ring, stick, tmp_path, probe):
    _, mount = stick
    key = ring.register(mount, remember=True)
    blob = ring.encrypt(b"data", key.key_id)
    elsewhere = KeyRing(
        tmp_path / "home",
        probe=probe,
        secret_store=FileSecretStore(tmp_path / "other-computer"),
    )
    with pytest.raises(PasswordRequiredError):
        elsewhere.decrypt(blob)


def test_copied_token_on_another_drive_is_refused(ring, stick, probe, tmp_path):
    device, mount = stick
    key = ring.register(mount, remember=True)
    blob = ring.encrypt(b"data", key.key_id)
    _, clone = add_stick(tmp_path, probe, "clone", "CC11223344556677", pid="3333")
    shutil.copytree(mount / ".usbtether", clone / ".usbtether")
    probe.remove(device)
    assert not ring.is_present(key.key_id)
    with pytest.raises(DriveVerificationError) as info:
        ring.decrypt(blob)
    assert info.value.reason == "device_mismatch"


def test_revoked_and_unknown_keys(ring, stick):
    _, mount = stick
    key = ring.register(mount, remember=True)
    blob = ring.encrypt(b"data", key.key_id)
    revoked = ring.revoke(key.key_id)
    assert not revoked.active and revoked.revoked_at
    assert ring.keys() == [] and ring.keys(include_revoked=True) == [revoked]
    with pytest.raises(KeyRevokedError):
        ring.decrypt(blob)
    with pytest.raises(UnknownKeyError):
        ring.get("not-a-uuid")
    with pytest.raises(UnknownKeyError):
        ring.encrypt(b"x", "00000000-0000-4000-8000-000000000000")


def test_files_use_the_vault_format(ring, stick, tmp_path):
    _, mount = stick
    key = ring.register(mount, remember=True)
    plain = tmp_path / "doc.txt"
    plain.write_bytes(b"file body")
    enc = ring.encrypt_file(plain, key.key_id, keep=True)
    assert enc.name == "doc.txt.utenc" and plain.exists()
    out = ring.decrypt_file(enc, dest_dir=tmp_path / "out", keep=True)
    assert out.read_bytes() == b"file body"
    # same key as `usbtether vault` / `usbtether open`
    vault_key = drive_key(ring.agent(), ring.verifier())
    assert decrypt_file(enc, vault_key, dest_dir=tmp_path / "out2").read_bytes() == b"file body"
    with pytest.raises(NotEncryptedError):
        ring.decrypt_file(plain)


def test_file_decrypt_without_key_id_needs_exactly_one_key(ring, stick, probe, tmp_path):
    _, mount = stick
    _, mount_b = add_stick(tmp_path, probe, "second", "BB99887766554433", pid="2222")
    a = ring.register(mount, remember=True)
    b = ring.register(mount_b, remember=True)
    plain = tmp_path / "doc.txt"
    plain.write_bytes(b"x")
    enc = ring.encrypt_file(plain, a.key_id)
    with pytest.raises(AmbiguousDeviceError):
        ring.decrypt_file(enc)
    with pytest.raises(TamperedError):  # wrong key for a .utenc file
        ring.decrypt_file(enc, b.key_id, keep=True)
    assert issubclass(TamperedError, VaultError)
    assert ring.decrypt_file(enc, a.key_id).read_bytes() == b"x"


def test_separate_homes_keep_separate_keys(stick, probe, tmp_path):
    _, mount = stick
    one = KeyRing(tmp_path / "one", probe=probe, secret_store=FileSecretStore(tmp_path / "s1"))
    two = KeyRing(tmp_path / "two", probe=probe, secret_store=FileSecretStore(tmp_path / "s2"))
    key = one.register(mount, remember=True)
    assert two.keys() == []
    with pytest.raises(UnknownKeyError):
        two.encrypt(b"x", key.key_id)
