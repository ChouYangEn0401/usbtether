import pytest

from usbtether import Agent, FileSecretStore, Verifier, enroll
from usbtether.errors import UsbTetherError
from usbtether.vault import (
    VaultError,
    VaultWatcher,
    decrypt_file,
    drive_key,
    encrypt_file,
    lock_folder,
    unlock_folder,
)


@pytest.fixture
def store(tmp_path):
    return FileSecretStore(tmp_path / "host-secrets")


def test_file_roundtrip_and_tamper_detection(tmp_path):
    key = b"k" * 32
    f = tmp_path / "a.txt"
    f.write_bytes(b"secret")
    enc = encrypt_file(f, key)
    assert not f.exists() and b"secret" not in enc.read_bytes()
    with pytest.raises(VaultError):
        decrypt_file(enc, b"x" * 32)
    assert enc.exists()  # a failed decrypt must not destroy the file
    assert decrypt_file(enc, key).read_bytes() == b"secret"


def test_folder_lock_unlock_is_idempotent(tmp_path):
    key = b"k" * 32
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_bytes(b"1")
    (tmp_path / "sub" / "b.txt").write_bytes(b"2")
    assert lock_folder(tmp_path, key).changed == 2
    assert lock_folder(tmp_path, key).changed == 0
    assert unlock_folder(tmp_path, key).changed == 2
    assert (tmp_path / "sub" / "b.txt").read_bytes() == b"2"


def test_the_same_drive_always_derives_the_same_key(stick, probe, registry, store):
    _, mount = stick
    enroll(probe, registry, mount, remember=True, secret_store=store)
    agent = Agent(probe, secret_store=store)
    verifier = Verifier(registry)
    assert drive_key(agent, verifier) == drive_key(agent, verifier)


def test_plugging_and_unplugging_the_drive_unlocks_and_locks(
    stick, probe, registry, store, tmp_path
):
    device, mount = stick
    enroll(probe, registry, mount, remember=True, secret_store=store)
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "note.txt").write_bytes(b"top secret")
    events: list[str] = []
    watcher = VaultWatcher(
        vault, Agent(probe, secret_store=store), Verifier(registry), on_event=events.append
    )

    watcher.step()  # drive present: plain folder stays readable
    assert watcher.unlocked and (vault / "note.txt").exists()

    probe.remove(device)
    watcher.step()  # drive gone: encrypted
    assert not watcher.unlocked
    assert not (vault / "note.txt").exists()
    assert b"top secret" not in (vault / "note.txt.utenc").read_bytes()

    probe.add(device)
    watcher.step()  # back: decrypted
    assert (vault / "note.txt").read_bytes() == b"top secret"


def test_a_different_drive_cannot_open_the_vault(stick, probe, registry, store, tmp_path):
    from .conftest import add_stick

    device, mount = stick
    enroll(probe, registry, mount, remember=True, secret_store=store)
    key = Agent(probe, secret_store=store).derive_key("vault-v1")
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "a.txt").write_bytes(b"x")
    lock_folder(vault, key)

    probe.remove(device)
    _, other = add_stick(tmp_path, probe, "other", "BB00112233445566")
    enroll(probe, registry, other, remember=True, secret_store=store)
    other_key = Agent(probe, secret_store=store).derive_key("vault-v1")
    assert other_key != key
    with pytest.raises(UsbTetherError):
        unlock_folder(vault, other_key)
    assert (vault / "a.txt.utenc").exists()
