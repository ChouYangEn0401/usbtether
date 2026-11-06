"""Enrollment: bind a fresh token on a drive to that drive's hardware identity."""

from __future__ import annotations

import contextlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ._util import utc_now_iso
from .agent import Agent
from .device import UsbDevice
from .errors import (
    AlreadyEnrolledError,
    RegistryError,
    SecretStoreError,
    TokenError,
    UnsupportedDeviceError,
    UsbTetherError,
)
from .probe.base import DeviceProbe
from .registry import Registry, RegistryEntry
from .secretstore import HostSecretStore, NullSecretStore, default_secret_store
from .token import Token, create_token, has_token, read_token, remove_token
from .verifier import Verifier

Protection = Literal["none", "passphrase", "host-secret"]


@dataclass(frozen=True)
class EnrollmentResult:
    token: Token
    device: UsbDevice
    entry: RegistryEntry
    revoked: tuple[str, ...]  # token ids superseded by this enrollment
    protection: Protection = "none"


def enroll(
    probe: DeviceProbe,
    registry: Registry,
    mount: str | os.PathLike[str],
    *,
    label: str | None = None,
    passphrase: bytes | None = None,
    remember: bool = False,
    secret_store: HostSecretStore | None = None,
    overwrite: bool = False,
) -> EnrollmentResult:
    """Enroll the drive mounted at ``mount``.

    Key protection (choose at most one):

    * neither: the private key is stored unencrypted on the drive;
    * ``passphrase``: encrypted, and the passphrase must be supplied whenever it is used;
    * ``remember``: encrypted with a random secret kept in the host secret store, so the
      drive unlocks automatically on this computer and is useless on its own.

    The sequence is: check the drive is bindable, refuse to clobber an existing enrollment
    (unless ``overwrite``), write the token, register its public key and device fingerprint,
    then run a real challenge-response as a self-test. If any step fails the token files, the
    registry entry and any stored secret are removed again, so a failed enrollment leaves
    nothing behind.
    """
    if remember and passphrase:
        raise UsbTetherError("choose either a passphrase or remember, not both")
    device, volume = probe.find_by_mount(mount)
    if not device.is_bindable:
        raise UnsupportedDeviceError(
            f"this drive cannot be bound: its serial number is {device.serial_quality.value}. "
            "usbtether refuses to enroll drives without a real hardware serial."
        )
    mount_path = str(volume.mount_point)
    fingerprint = device.fingerprint

    superseded: set[str] = {e.token_id for e in registry.active_for_fingerprint(fingerprint)}
    if has_token(mount_path):
        with contextlib.suppress(TokenError):  # a corrupt old token is simply replaced
            superseded.add(read_token(mount_path).token_id)
    if superseded and not overwrite:
        raise AlreadyEnrolledError(
            "this drive is already enrolled; pass overwrite=True (--force) to enroll it again "
            "and revoke the previous token"
        )

    store = secret_store or default_secret_store()
    host_secret = secrets.token_hex(32).encode("ascii") if remember else None
    token = create_token(mount_path, host_secret or passphrase, overwrite=overwrite)
    entry = RegistryEntry(
        token_id=token.token_id,
        public_key=token.public_key_b64,
        fingerprint=fingerprint,
        device=device.report(volume).to_dict(),
        enrolled_at=utc_now_iso(),
        label=label,
    )
    stored = False
    try:
        registry.add(entry)
        if host_secret is not None:
            store.put(token.token_id, host_secret)
            stored = True
        agent = Agent(
            probe,
            passphrase=passphrase,
            secret_store=store if remember else NullSecretStore(),
        )
        outcome = Verifier(registry).authenticate(agent, "enrollment-selftest", mount_path)
        if not outcome.ok:
            raise UsbTetherError(
                f"enrollment self-test failed ({outcome.reason.value if outcome.reason else '?'})"
            )
    except BaseException:
        registry.remove(token.token_id)
        if stored:
            with contextlib.suppress(SecretStoreError):
                store.delete(token.token_id)
        remove_token(Path(mount_path))
        raise

    revoked: list[str] = []
    for old_id in sorted(superseded - {token.token_id}):
        with contextlib.suppress(SecretStoreError):  # a stale secret must not linger
            store.delete(old_id)
        with contextlib.suppress(RegistryError):  # not registered on this host: nothing to revoke
            registry.revoke(old_id)
            revoked.append(old_id)
    protection: Protection = "host-secret" if remember else ("passphrase" if passphrase else "none")
    return EnrollmentResult(token, device, entry, tuple(revoked), protection)
