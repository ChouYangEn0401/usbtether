import os
import stat
import sys
import uuid
from pathlib import Path

import pytest

from usbtether.errors import SecretStoreError
from usbtether.secretstore import (
    DpapiSecretStore,
    FileSecretStore,
    NullSecretStore,
    default_secret_store,
)

TOKEN = str(uuid.uuid4())


def test_file_store_roundtrip(tmp_path):
    store = FileSecretStore(tmp_path / "secrets")
    assert store.get(TOKEN) is None
    store.put(TOKEN, b"s3cret")
    assert store.get(TOKEN) == b"s3cret"
    store.put(TOKEN, b"replaced")
    assert store.get(TOKEN) == b"replaced"
    store.delete(TOKEN)
    assert store.get(TOKEN) is None
    store.delete(TOKEN)  # deleting twice is fine


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_file_store_files_are_owner_only(tmp_path):
    store = FileSecretStore(tmp_path)
    store.put(TOKEN, b"x")
    mode = stat.S_IMODE(os.stat(tmp_path / f"{TOKEN}.bin").st_mode)
    assert mode == 0o600


@pytest.mark.parametrize("bad", ["../evil", "not-a-uuid", "", "a/b", "..\\evil"])
def test_token_ids_cannot_escape_the_directory(tmp_path, bad):
    store = FileSecretStore(tmp_path / "secrets")
    for call in (lambda: store.get(bad), lambda: store.put(bad, b"x"), lambda: store.delete(bad)):
        with pytest.raises(SecretStoreError):
            call()
    assert not any(Path(tmp_path).rglob("evil*"))


def test_null_store():
    store = NullSecretStore()
    assert store.get(TOKEN) is None
    store.delete(TOKEN)
    with pytest.raises(SecretStoreError):
        store.put(TOKEN, b"x")


def test_default_store_follows_the_platform_and_home(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.platform", "linux")
    store = default_secret_store(tmp_path)
    assert isinstance(store, FileSecretStore)
    assert store.directory == tmp_path / "secrets"
    monkeypatch.setattr("sys.platform", "win32")
    assert isinstance(default_secret_store(tmp_path), DpapiSecretStore)


def test_default_store_uses_usbtether_home(monkeypatch, tmp_path):
    monkeypatch.setenv("USBTETHER_HOME", str(tmp_path))
    monkeypatch.setattr("sys.platform", "linux")
    assert default_secret_store().directory == tmp_path / "secrets"


@pytest.mark.skipif(sys.platform == "win32", reason="DPAPI exists here")
def test_dpapi_store_refuses_other_platforms(tmp_path):
    from usbtether.errors import UnsupportedPlatformError

    with pytest.raises(UnsupportedPlatformError):
        DpapiSecretStore(tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows only")
def test_dpapi_roundtrip_and_files_are_not_plaintext(tmp_path):
    """Run this on Windows: it exercises the real CryptProtectData / CryptUnprotectData."""
    store = DpapiSecretStore(tmp_path)
    secret = b"0123456789abcdef" * 4
    store.put(TOKEN, secret)
    on_disk = (tmp_path / f"{TOKEN}.bin").read_bytes()
    assert secret not in on_disk
    assert store.get(TOKEN) == secret
    (tmp_path / f"{TOKEN}.bin").write_bytes(on_disk[:-3] + b"xyz")  # corrupt the blob
    with pytest.raises(SecretStoreError, match="cannot unprotect the stored secret"):
        store.get(TOKEN)
