"""Host-side secret store: unlock a protected key without typing a passphrase.

With ``--remember`` the private key on the drive is encrypted with a random secret that
**never touches the drive**. The secret is kept here, on the computer:

* Windows: sealed with DPAPI (``CryptProtectData``), bound to the current Windows user.
* Other platforms: a file readable only by its owner. This protects against *losing the
  drive*, but not against anyone who can read your files.

A drive that is lost or stolen on its own is therefore useless, while on this computer it
unlocks with no interaction. The trade-off is that the unlock is tied to this computer and
user account: it does not follow the drive to other computers. See ``docs/threat-model.md``.
"""

from __future__ import annotations

import abc
import sys
import uuid
from pathlib import Path

from ._util import atomic_write
from .errors import SecretStoreError, UnsupportedPlatformError
from .registry import default_home


class HostSecretStore(abc.ABC):
    """Maps a token id to the secret that unlocks its private key."""

    @abc.abstractmethod
    def get(self, token_id: str) -> bytes | None: ...

    @abc.abstractmethod
    def put(self, token_id: str, secret: bytes) -> None: ...

    @abc.abstractmethod
    def delete(self, token_id: str) -> None: ...


class NullSecretStore(HostSecretStore):
    """Stores nothing. Use it to make sure no host secret is consulted."""

    def get(self, token_id: str) -> bytes | None:
        return None

    def put(self, token_id: str, secret: bytes) -> None:
        raise SecretStoreError("this secret store cannot store secrets")

    def delete(self, token_id: str) -> None:
        return None


class _FileBackedStore(HostSecretStore):
    """One file per token in ``directory``; subclasses decide how contents are protected."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def _path(self, token_id: str) -> Path:
        try:
            canonical = str(uuid.UUID(token_id))
        except ValueError as exc:  # also blocks path traversal through the file name
            raise SecretStoreError(f"invalid token id {token_id!r}") from exc
        return self.directory / f"{canonical}.bin"

    @abc.abstractmethod
    def _seal(self, secret: bytes) -> bytes: ...

    @abc.abstractmethod
    def _unseal(self, blob: bytes) -> bytes: ...

    def get(self, token_id: str) -> bytes | None:
        path = self._path(token_id)
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SecretStoreError(f"cannot read the stored secret for this token: {exc}") from exc
        return self._unseal(blob)

    def put(self, token_id: str, secret: bytes) -> None:
        path = self._path(token_id)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            atomic_write(path, self._seal(secret), private=True)
        except OSError as exc:
            raise SecretStoreError(f"cannot store the secret: {exc}") from exc

    def delete(self, token_id: str) -> None:
        try:
            self._path(token_id).unlink(missing_ok=True)
        except OSError as exc:
            raise SecretStoreError(f"cannot delete the stored secret: {exc}") from exc


class FileSecretStore(_FileBackedStore):
    """Owner-only files, otherwise unprotected. Used where no OS key store is wired in."""

    def _seal(self, secret: bytes) -> bytes:
        return secret

    def _unseal(self, blob: bytes) -> bytes:
        return blob


class DpapiSecretStore(_FileBackedStore):
    """Windows DPAPI: only the same Windows user on the same machine can read the files."""

    def __init__(self, directory: str | Path) -> None:
        if sys.platform != "win32":
            raise UnsupportedPlatformError("DPAPI is only available on Windows")
        super().__init__(directory)

    def _seal(self, secret: bytes) -> bytes:
        return _dpapi(secret, protect=True)

    def _unseal(self, blob: bytes) -> bytes:
        return _dpapi(blob, protect=False)


def _dpapi(data: bytes, *, protect: bool) -> bytes:
    """Call CryptProtectData / CryptUnprotectData for the current user."""
    if sys.platform != "win32":
        raise UnsupportedPlatformError("DPAPI is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    blob_ptr = ctypes.POINTER(DataBlob)
    if protect:
        function = crypt32.CryptProtectData
        function.argtypes = [
            blob_ptr,
            wintypes.LPCWSTR,
            blob_ptr,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            blob_ptr,
        ]
    else:
        function = crypt32.CryptUnprotectData
        function.argtypes = [
            blob_ptr,
            ctypes.POINTER(wintypes.LPWSTR),
            blob_ptr,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            blob_ptr,
        ]
    function.restype = wintypes.BOOL

    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = DataBlob()
    ui_forbidden = 0x1  # CRYPTPROTECT_UI_FORBIDDEN: never pop up a dialog
    if protect:
        ok = function(
            ctypes.byref(blob_in),
            "usbtether",
            None,
            None,
            None,
            ui_forbidden,
            ctypes.byref(blob_out),
        )
    else:
        ok = function(
            ctypes.byref(blob_in), None, None, None, None, ui_forbidden, ctypes.byref(blob_out)
        )
    if not ok:
        reason = ctypes.WinError(ctypes.get_last_error())
        message = (
            "cannot protect the stored secret" if protect else "cannot unprotect the stored secret"
        )
        raise SecretStoreError(f"{message} (was it saved by another Windows user?): {reason}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def default_secret_store(home: str | Path | None = None) -> HostSecretStore:
    """The store for this platform, under ``<home>/secrets`` (default: the usbtether home)."""
    directory = Path(home) / "secrets" if home else default_home() / "secrets"
    if sys.platform == "win32":
        return DpapiSecretStore(directory)
    return FileSecretStore(directory)
