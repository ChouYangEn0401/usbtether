"""Enrollment: bind a fresh token on a drive to that drive's hardware identity."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path

from ._util import utc_now_iso
from .agent import Agent
from .device import UsbDevice
from .errors import (
    AlreadyEnrolledError,
    RegistryError,
    TokenError,
    UnsupportedDeviceError,
    UsbTetherError,
)
from .probe.base import DeviceProbe
from .registry import Registry, RegistryEntry
from .token import Token, create_token, has_token, read_token, remove_token
from .verifier import Verifier


@dataclass(frozen=True)
class EnrollmentResult:
    token: Token
    device: UsbDevice
    entry: RegistryEntry
    revoked: tuple[str, ...]  # token ids superseded by this enrollment


def enroll(
    probe: DeviceProbe,
    registry: Registry,
    mount: str | os.PathLike[str],
    *,
    label: str | None = None,
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> EnrollmentResult:
    """Enroll the drive mounted at ``mount``.

    The sequence is: check the drive is bindable, refuse to clobber an existing enrollment
    (unless ``overwrite``), write the token, register its public key and device fingerprint,
    then run a real challenge-response as a self-test. If any step fails the token files and
    the registry entry are removed again, so a failed enrollment leaves nothing behind.
    """
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

    token = create_token(mount_path, passphrase, overwrite=overwrite)
    entry = RegistryEntry(
        token_id=token.token_id,
        public_key=token.public_key_b64,
        fingerprint=fingerprint,
        device=device.report(volume).to_dict(),
        enrolled_at=utc_now_iso(),
        label=label,
    )
    try:
        registry.add(entry)
        outcome = Verifier(registry).authenticate(
            Agent(probe, passphrase=passphrase), "enrollment-selftest", mount_path
        )
        if not outcome.ok:
            raise UsbTetherError(
                f"enrollment self-test failed ({outcome.reason.value if outcome.reason else '?'})"
            )
    except BaseException:
        registry.remove(token.token_id)
        remove_token(Path(mount_path))
        raise

    revoked: list[str] = []
    for old_id in sorted(superseded - {token.token_id}):
        with contextlib.suppress(RegistryError):  # not registered on this host: nothing to revoke
            registry.revoke(old_id)
            revoked.append(old_id)
    return EnrollmentResult(token, device, entry, tuple(revoked))
