"""Library core: register USB drives as keys and encrypt or decrypt with them.

This module is a thin, stable facade over the rest of the package. It adds no new
cryptography: every operation runs the same challenge-response check as the CLI
(:meth:`Verifier.authenticate`) and then uses :meth:`Agent.derive_key` and AES-256-GCM, exactly
like ``usbtether vault``. Typical use::

    from usbtether.core import KeyRing

    ring = KeyRing()                      # or KeyRing(home="path/to/my/store")
    for drive in ring.drives():           # plugged-in USB drives
        print(drive.mount_point, drive.bindable, drive.key_id)
    key = ring.register("E:", label="desk key", remember=True)
    blob = ring.encrypt(b"hello", key.key_id)
    assert ring.decrypt(blob) == b"hello"  # needs that drive plugged in

Where things live:

* the **key metadata** (public key, drive fingerprint, label) is in ``<home>/registry.json``;
* a ``remember=True`` key's unlock secret is in ``<home>/secrets`` (DPAPI on Windows);
* the **private key** stays on the USB drive, in ``<drive>/.usbtether``.

``home`` defaults to the usual per-user directory (``%APPDATA%\\usbtether`` on Windows, or the
``USBTETHER_HOME`` variable), which is shared with the CLI and the desktop app. Pass your own
``home`` (or ``registry`` and ``secret_store``) to keep a separate set of keys.

Security level: convenience-grade, see ``docs/threat-model.md``. An ordinary USB drive cannot
hide a key; this stops casual copying, not a determined attacker.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import vault
from .agent import Agent, PassphraseSource, TokenCandidate
from .device import Volume
from .enrollment import enroll
from .errors import (
    AmbiguousDeviceError,
    DriveVerificationError,
    KeyNotPresentError,
    KeyRevokedError,
    NotEncryptedError,
    SecretStoreError,
    TamperedError,
    UnknownKeyError,
    UnsupportedDeviceError,
    WrongKeyError,
)
from .probe import DeviceProbe, InMemoryProbe, default_probe
from .protocol import FailureReason
from .registry import Registry, RegistryEntry, default_home
from .secretstore import HostSecretStore, default_secret_store
from .verifier import Verifier

__all__ = [
    "DATA_LABEL",
    "DATA_MAGIC",
    "MESSAGE_PREFIX",
    "Drive",
    "KeyRecord",
    "KeyRing",
    "Password",
]

DATA_MAGIC = b"UTD1"
"""First bytes of an :meth:`KeyRing.encrypt` result."""
DATA_LABEL = "data-v1"
"""``derive_key`` label for bytes and messages (files use :data:`usbtether.vault.LABEL`)."""
MESSAGE_PREFIX = "utmsg1:"
"""Prefix of an :meth:`KeyRing.encrypt_message` result."""

_NONCE = 12
_TAG = 16
_HEADER = len(DATA_MAGIC) + 16  # magic + key id (UUID bytes)

Password = str | bytes | Callable[[], bytes | None] | None
"""A password: text, bytes, or a callable that is asked only when a password is needed."""


@dataclass(frozen=True)
class KeyRecord:
    """A registered USB key. Contains no secret: the private key never leaves the drive."""

    key_id: str
    label: str | None
    fingerprint: str  # SHA-256 of the drive's (vendor id, product id, serial); not secret
    vendor_id: str
    product_id: str
    product: str | None
    registered_at: str
    active: bool
    revoked_at: str | None = None

    @classmethod
    def from_entry(cls, entry: RegistryEntry) -> KeyRecord:
        device = entry.device
        return cls(
            key_id=entry.token_id,
            label=entry.label,
            fingerprint=entry.fingerprint,
            vendor_id=str(device.get("vendor_id", "")),
            product_id=str(device.get("product_id", "")),
            product=None if device.get("product") is None else str(device["product"]),
            registered_at=entry.enrolled_at,
            active=entry.is_active,
            revoked_at=entry.revoked_at,
        )


@dataclass(frozen=True)
class Drive:
    """A plugged-in USB drive (one entry per mounted volume, or one for an unmounted drive)."""

    mount_point: str | None
    vendor_id: str
    product_id: str
    product: str | None
    volume_label: str | None
    capacity: int | None
    serial_quality: str  # "good" means the drive can be registered
    fingerprint: str | None  # None when the drive has no usable serial
    key_id: str | None  # id of the usbtether token on the drive, if any
    registered: bool  # key_id is an active key in this KeyRing

    @property
    def bindable(self) -> bool:
        return self.serial_quality == "good"


def _as_source(password: Password) -> PassphraseSource:
    if isinstance(password, str):
        return password.encode("utf-8")
    return password


class KeyRing:
    """Registered USB keys plus encrypt/decrypt with any of them.

    ``home`` chooses where key metadata and remembered secrets are kept (see the module
    docstring); ``registry`` and ``secret_store`` override the two parts separately. ``probe``
    is how drives are discovered; pass :class:`~usbtether.InMemoryProbe` in tests. ``password``
    is the default password source for protected keys (each call can pass its own).
    """

    def __init__(
        self,
        home: str | os.PathLike[str] | None = None,
        *,
        registry: Registry | None = None,
        secret_store: HostSecretStore | None = None,
        probe: DeviceProbe | None = None,
        password: Password = None,
    ) -> None:
        self.home = Path(home) if home is not None else default_home()
        self.registry = registry or Registry(self.home / "registry.json")
        self._secret_store = secret_store
        self._probe = probe
        self._password = password

    # -- plumbing ------------------------------------------------------------------------

    @property
    def secret_store(self) -> HostSecretStore:
        if self._secret_store is None:
            self._secret_store = default_secret_store(self.home)
        return self._secret_store

    @property
    def probe(self) -> DeviceProbe:
        if self._probe is None:
            self._probe = default_probe()
        return self._probe

    def _snapshot(self) -> DeviceProbe:
        # One OS query per operation (the Windows probe takes about two seconds).
        return InMemoryProbe(self.probe.list_devices())

    def agent(self, password: Password = None, *, probe: DeviceProbe | None = None) -> Agent:
        """An :class:`Agent` wired to this key ring's secret store (for ``VaultWatcher`` etc.)."""
        return Agent(
            probe or self.probe,
            passphrase=_as_source(password if password is not None else self._password),
            secret_store=self.secret_store,
        )

    def verifier(self) -> Verifier:
        """A :class:`Verifier` over this key ring's registry."""
        return Verifier(self.registry)

    # -- drives and keys -----------------------------------------------------------------

    def drives(self) -> list[Drive]:
        """Every attached USB mass-storage drive, and whether it can be or is registered."""
        active = {e.token_id for e in self.registry.entries() if e.is_active}
        snapshot = self._snapshot()
        tokens = {c.mount_point: c.token.token_id for c in self.agent(probe=snapshot).candidates()}
        result: list[Drive] = []
        for device in snapshot.list_devices():
            fingerprint = device.fingerprint if device.is_bindable else None
            volumes: list[Volume | None] = [v for v in device.volumes if v.mount_point] or [None]
            for volume in volumes:
                mount = volume.mount_point if volume else None
                key_id = tokens.get(mount) if mount else None
                result.append(
                    Drive(
                        mount_point=mount,
                        vendor_id=device.vendor_id,
                        product_id=device.product_id,
                        product=device.product,
                        volume_label=volume.label if volume else None,
                        capacity=device.capacity,
                        serial_quality=device.serial_quality.value,
                        fingerprint=fingerprint,
                        key_id=key_id,
                        registered=key_id in active,
                    )
                )
        return result

    def register(
        self,
        mount: str | os.PathLike[str],
        *,
        label: str | None = None,
        password: str | bytes | None = None,
        remember: bool = False,
        overwrite: bool = False,
    ) -> KeyRecord:
        """Make the drive at ``mount`` a key (same as ``usbtether enroll``).

        ``password`` protects the key with a password; ``remember=True`` instead protects it
        with a secret kept on this computer, so it unlocks without typing but only here.
        ``overwrite=True`` re-registers a drive and revokes its old key: data encrypted with
        the old key can then no longer be decrypted.
        """
        secret = password.encode("utf-8") if isinstance(password, str) else password
        result = enroll(
            self.probe,
            self.registry,
            mount,
            label=label,
            passphrase=secret,
            remember=remember,
            secret_store=self.secret_store,
            overwrite=overwrite,
        )
        return KeyRecord.from_entry(result.entry)

    def keys(self, *, include_revoked: bool = False) -> list[KeyRecord]:
        """Registered keys, oldest first."""
        return [
            KeyRecord.from_entry(e)
            for e in self.registry.entries()
            if include_revoked or e.is_active
        ]

    def get(self, key_id: str) -> KeyRecord:
        """The record for ``key_id``; :class:`UnknownKeyError` if it is not registered."""
        return KeyRecord.from_entry(self._entry(key_id))

    def revoke(self, key_id: str) -> KeyRecord:
        """Revoke a key and forget its remembered secret. Its data can no longer be decrypted."""
        self._entry(key_id)
        entry = self.registry.revoke(key_id)
        with contextlib.suppress(SecretStoreError):
            self.secret_store.delete(key_id)
        return KeyRecord.from_entry(entry)

    def present_keys(self) -> list[KeyRecord]:
        """Active keys whose drive is plugged in right now.

        This is a quick look (token id and drive fingerprint), not proof: every encrypt and
        decrypt runs the full challenge-response check.
        """
        entries = {e.token_id: e for e in self.registry.entries() if e.is_active}
        found: dict[str, KeyRecord] = {}
        for candidate in self.agent(probe=self._snapshot()).candidates():
            entry = entries.get(candidate.token.token_id)
            if entry is not None and _matches(candidate, entry):
                found.setdefault(entry.token_id, KeyRecord.from_entry(entry))
        return list(found.values())

    def is_present(self, key_id: str) -> bool:
        """True if the drive of ``key_id`` is plugged in (see :meth:`present_keys`)."""
        return any(k.key_id == key_id for k in self.present_keys())

    # -- key derivation ------------------------------------------------------------------

    def _entry(self, key_id: str) -> RegistryEntry:
        try:
            canonical = str(uuid.UUID(key_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise UnknownKeyError(f"{key_id!r} is not a key id") from exc
        entry = self.registry.get(canonical)
        if entry is None:
            raise UnknownKeyError(f"key {canonical} is not registered")
        return entry

    def derive(self, key_id: str, label: str, *, password: Password = None) -> bytes:
        """Check the drive of ``key_id`` (challenge-response) and derive the key for ``label``.

        Raises :class:`UnknownKeyError`, :class:`KeyRevokedError`, :class:`KeyNotPresentError`,
        :class:`PasswordRequiredError` / :class:`WrongPasswordError`, or
        :class:`DriveVerificationError` (for example a copied token on another drive).
        """
        entry = self._entry(key_id)
        if not entry.is_active:
            raise KeyRevokedError(f"key {entry.token_id} has been revoked")
        agent = self.agent(password, probe=self._snapshot())
        mounts = [c.mount_point for c in agent.candidates() if c.token.token_id == entry.token_id]
        if not mounts:
            label_text = f" ({entry.label})" if entry.label else ""
            raise KeyNotPresentError(
                f"the drive of key {entry.token_id}{label_text} is not plugged in"
            )
        verifier = self.verifier()
        error: DriveVerificationError | None = None
        for mount in mounts:  # normally one; a copied token on a second drive fails the check
            try:
                return vault.drive_key(agent, verifier, mount, label=label)
            except DriveVerificationError as exc:
                if exc.reason == FailureReason.TOKEN_REVOKED.value:
                    raise KeyRevokedError(f"key {entry.token_id} has been revoked") from exc
                error = exc
        assert error is not None
        raise error

    def file_key(self, key_id: str, *, password: Password = None) -> bytes:
        """The key used for ``.utenc`` files and folder vaults (``usbtether vault`` / ``open``)."""
        return self.derive(key_id, vault.LABEL, password=password)

    def _only_present_key(self) -> str:
        present = self.present_keys()
        if not present:
            raise KeyNotPresentError("no registered key is plugged in")
        if len(present) > 1:
            raise AmbiguousDeviceError("several registered keys are plugged in; pass key_id")
        return present[0].key_id

    # -- bytes and messages --------------------------------------------------------------

    def encrypt(self, data: bytes, key_id: str, *, password: Password = None) -> bytes:
        """Encrypt ``data`` with the key ``key_id`` (its drive must be plugged in).

        Format: ``b"UTD1" + key id (16 bytes) + nonce (12) + AES-256-GCM ciphertext and tag``;
        the first 20 bytes are authenticated as associated data.
        """
        entry = self._entry(key_id)
        key = self.derive(entry.token_id, DATA_LABEL, password=password)
        header = DATA_MAGIC + uuid.UUID(entry.token_id).bytes
        nonce = secrets.token_bytes(_NONCE)
        return header + nonce + AESGCM(key).encrypt(nonce, bytes(data), header)

    @staticmethod
    def key_id_of(blob: bytes) -> str:
        """The key id an :meth:`encrypt` result was made with (no drive needed)."""
        if len(blob) < _HEADER + _NONCE + _TAG or not blob.startswith(DATA_MAGIC):
            raise NotEncryptedError("not usbtether data (wrong format or truncated)")
        return str(uuid.UUID(bytes=bytes(blob[len(DATA_MAGIC) : _HEADER])))

    def decrypt(
        self, blob: bytes, *, key_id: str | None = None, password: Password = None
    ) -> bytes:
        """Decrypt an :meth:`encrypt` result. The key is read from the data itself.

        ``key_id``, if given, must match it (:class:`WrongKeyError` otherwise). Altered data
        raises :class:`TamperedError`.
        """
        blob = bytes(blob)
        embedded = self.key_id_of(blob)
        if key_id is not None and str(self._entry(key_id).token_id) != embedded:
            raise WrongKeyError(f"this data was encrypted with key {embedded}, not {key_id}")
        key = self.derive(embedded, DATA_LABEL, password=password)
        header, nonce = blob[:_HEADER], blob[_HEADER : _HEADER + _NONCE]
        try:
            return AESGCM(key).decrypt(nonce, blob[_HEADER + _NONCE :], header)
        except InvalidTag as exc:
            raise TamperedError("cannot decrypt: the data was altered") from exc

    def encrypt_message(self, text: str, key_id: str, *, password: Password = None) -> str:
        """Encrypt text into a copy-pasteable ASCII string (``utmsg1:`` + base64url)."""
        blob = self.encrypt(text.encode("utf-8"), key_id, password=password)
        return MESSAGE_PREFIX + base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")

    def decrypt_message(
        self, message: str, *, key_id: str | None = None, password: Password = None
    ) -> str:
        """Decrypt an :meth:`encrypt_message` result."""
        text = message.strip()
        if not text.startswith(MESSAGE_PREFIX):
            raise NotEncryptedError("not a usbtether message")
        body = text[len(MESSAGE_PREFIX) :]
        try:
            blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError) as exc:
            raise NotEncryptedError("not a usbtether message (bad encoding)") from exc
        data = self.decrypt(blob, key_id=key_id, password=password)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TamperedError("decrypted message is not text") from exc

    # -- files ---------------------------------------------------------------------------

    def encrypt_file(
        self,
        path: str | os.PathLike[str],
        key_id: str,
        *,
        dest_dir: str | os.PathLike[str] | None = None,
        keep: bool = False,
        password: Password = None,
    ) -> Path:
        """Encrypt a file to ``<name>.utenc`` (the format of ``usbtether vault`` / ``open``).

        By default the original is deleted; ``keep=True`` leaves it. Returns the new path.
        """
        key = self.file_key(key_id, password=password)
        return vault.encrypt_file(
            Path(path), key, dest_dir=Path(dest_dir) if dest_dir else None, keep=keep
        )

    def decrypt_file(
        self,
        path: str | os.PathLike[str],
        key_id: str | None = None,
        *,
        dest_dir: str | os.PathLike[str] | None = None,
        keep: bool = False,
        password: Password = None,
    ) -> Path:
        """Decrypt a ``.utenc`` file. ``.utenc`` files do not record their key, so without
        ``key_id`` the only registered key that is plugged in is used."""
        source = Path(path)
        if not source.name.endswith(vault.SUFFIX):
            raise NotEncryptedError(f"{source.name} is not a {vault.SUFFIX} file")
        key = self.file_key(key_id or self._only_present_key(), password=password)
        return vault.decrypt_file(
            source, key, dest_dir=Path(dest_dir) if dest_dir else None, keep=keep
        )


def _matches(candidate: TokenCandidate, entry: RegistryEntry) -> bool:
    try:
        return candidate.device.fingerprint == entry.fingerprint
    except UnsupportedDeviceError:
        return False
