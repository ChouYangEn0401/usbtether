"""A small file vault: files in a folder are AES-256-GCM encrypted unless the drive is plugged in.

The key is derived from the enrolled drive's token (:meth:`Agent.derive_key`), after the drive
has also passed a normal challenge-response. ``unlock`` decrypts the folder, ``lock`` encrypts it.
:class:`VaultWatcher` does both automatically as the drive is plugged in and removed.

Honest limits: while the folder is unlocked its files are plain files that any program running
as you can read, and the key lives in this process's memory. If the process is killed while
unlocked, the files stay readable until you run ``lock``. The key derives from a file on the
drive, so a copy of that file (plus the passphrase, if one is set) opens the vault.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .agent import Agent
from .errors import UsbTetherError
from .verifier import Verifier

MAGIC = b"UTV1"
SUFFIX = ".utenc"
LABEL = "vault-v1"


class VaultError(UsbTetherError):
    """A vault file could not be encrypted or decrypted."""


@dataclass(frozen=True)
class VaultResult:
    changed: int
    skipped: int


def encrypt_file(
    path: Path, key: bytes, *, dest_dir: Path | None = None, keep: bool = False
) -> Path:
    """Encrypt ``path`` into ``<name>.utenc``.

    By default the result sits next to the original and the original is deleted. ``dest_dir``
    writes it elsewhere instead; ``keep=True`` leaves the original in place.
    """
    target = (dest_dir or path.parent) / (path.name + SUFFIX)
    target.parent.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_bytes(12)
    blob = MAGIC + nonce + AESGCM(key).encrypt(nonce, path.read_bytes(), path.name.encode())
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, target)
    if not keep:
        path.unlink()
    return target


def decrypt_file(
    path: Path, key: bytes, *, dest_dir: Path | None = None, keep: bool = False
) -> Path:
    """Decrypt a ``.utenc`` file back to its original name (same options as ``encrypt_file``)."""
    original = path.name[: -len(SUFFIX)]
    blob = path.read_bytes()
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 12 + 16:
        raise VaultError(f"{path.name} is not a usbtether vault file")
    nonce = blob[len(MAGIC) : len(MAGIC) + 12]
    try:
        data = AESGCM(key).decrypt(nonce, blob[len(MAGIC) + 12 :], original.encode())
    except InvalidTag as exc:
        raise VaultError(f"cannot decrypt {path.name}: wrong key or the file was altered") from exc
    target = (dest_dir or path.parent) / original
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    if not keep:
        path.unlink()
    return target


def _files(folder: Path) -> list[Path]:
    return sorted(p for p in folder.rglob("*") if p.is_file() and not p.name.endswith(".tmp"))


def lock_folder(folder: Path, key: bytes) -> VaultResult:
    changed = skipped = 0
    for path in _files(folder):
        if path.name.endswith(SUFFIX):
            skipped += 1
        else:
            encrypt_file(path, key)
            changed += 1
    return VaultResult(changed, skipped)


def unlock_folder(folder: Path, key: bytes) -> VaultResult:
    changed = skipped = 0
    for path in _files(folder):
        if path.name.endswith(SUFFIX):
            decrypt_file(path, key)
            changed += 1
        else:
            skipped += 1
    return VaultResult(changed, skipped)


def drive_key(agent: Agent, verifier: Verifier, mount: str | None = None) -> bytes:
    """Prove the drive is genuine (challenge-response), then derive the vault key."""
    result = verifier.authenticate(agent, "vault-key", mount)
    if not result.ok:
        reason = result.reason.value if result.reason else "failed"
        raise VaultError(f"drive verification failed: {reason}")
    return agent.derive_key(LABEL, mount)


class VaultWatcher:
    """Unlock the folder when the enrolled drive appears; lock it when the drive is gone."""

    def __init__(
        self,
        folder: Path,
        agent: Agent,
        verifier: Verifier,
        *,
        on_event: Callable[[str], None] = lambda _: None,
    ) -> None:
        self._folder = folder
        self._agent = agent
        self._verifier = verifier
        self._emit = on_event
        self._key: bytes | None = None

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def step(self) -> None:
        """One poll. Safe to call repeatedly."""
        present = bool(self._agent.candidates())
        if present and self._key is None:
            try:
                key = drive_key(self._agent, self._verifier)
                result = unlock_folder(self._folder, key)
            except UsbTetherError as exc:
                self._emit(f"not unlocked: {exc}")
                return
            self._key = key
            self._emit(f"drive present: unlocked {result.changed} file(s)")
        elif not present and self._key is not None:
            result = lock_folder(self._folder, self._key)
            self._key = None  # best effort: Python cannot reliably wipe memory
            self._emit(f"drive removed: locked {result.changed} file(s)")

    def run(self, interval: float = 1.0) -> None:
        try:
            while True:
                self.step()
                time.sleep(interval)
        finally:
            if self._key is not None:
                lock_folder(self._folder, self._key)
                self._key = None
                self._emit("stopped: folder locked")
