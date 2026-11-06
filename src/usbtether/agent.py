"""The agent runs where the USB drive is plugged in: it reads the token and signs challenges.

It also reports which drive it is talking to. That report is signed together with the
challenge, but it is a *claim* of the agent: a verifier on another machine can only trust
it as far as it trusts the agent's host (see ``docs/threat-model.md``).
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass

from .device import UsbDevice, Volume
from .errors import (
    AmbiguousDeviceError,
    DeviceNotFoundError,
    ProtocolError,
    TokenError,
    UnsupportedDeviceError,
)
from .probe.base import DeviceProbe
from .protocol import Challenge, Response, b64url_encode, signing_payload
from .secretstore import HostSecretStore, default_secret_store
from .token import Token, has_token, load_private_key, read_token

PassphraseSource = bytes | Callable[[], bytes | None] | None


@dataclass(frozen=True)
class TokenCandidate:
    """An enrolled drive that is currently plugged in."""

    device: UsbDevice
    volume: Volume
    token: Token

    @property
    def mount_point(self) -> str:
        assert self.volume.mount_point is not None  # candidates always come from mounted volumes
        return self.volume.mount_point


class Agent:
    """Signs challenges with the token on a plugged-in drive.

    If the private key is encrypted, the secret is taken from the host secret store (see
    :mod:`usbtether.secretstore`) when it holds one for this token, and otherwise from
    ``passphrase`` (bytes, or a callable that is only invoked when it is actually needed).
    ``secret_store=None`` means the default store of this platform and user.
    """

    def __init__(
        self,
        probe: DeviceProbe,
        *,
        passphrase: PassphraseSource = None,
        secret_store: HostSecretStore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._probe = probe
        self._passphrase = passphrase
        self._secret_store = secret_store
        self._clock = clock

    def _unlock_secret(self, token_id: str) -> bytes | None:
        if self._secret_store is None:
            self._secret_store = default_secret_store()
        stored = self._secret_store.get(token_id)
        if stored is not None:
            return stored
        return self._passphrase() if callable(self._passphrase) else self._passphrase

    def candidates(self) -> list[TokenCandidate]:
        """Every plugged-in drive that carries a readable token."""
        found: list[TokenCandidate] = []
        for device in self._probe.list_devices():
            for volume in device.volumes:
                if not volume.mount_point or not has_token(volume.mount_point):
                    continue
                try:
                    token = read_token(volume.mount_point)
                except TokenError:
                    continue
                found.append(TokenCandidate(device, volume, token))
        return found

    def _select(self, mount: str | os.PathLike[str] | None) -> TokenCandidate:
        if mount is not None:
            device, volume = self._probe.find_by_mount(mount)
            if not volume.mount_point:
                raise DeviceNotFoundError(f"{os.fspath(mount)!r} has no mount point")
            return TokenCandidate(device, volume, read_token(volume.mount_point))
        candidates = self.candidates()
        if not candidates:
            raise DeviceNotFoundError("no USB drive with a usbtether token is plugged in")
        if len(candidates) > 1:
            names = ", ".join(c.mount_point for c in candidates)
            raise AmbiguousDeviceError(f"several enrolled drives are plugged in ({names})")
        return candidates[0]

    def respond(
        self, challenge: Challenge, mount: str | os.PathLike[str] | None = None
    ) -> Response:
        """Sign ``challenge`` with the token on the drive at ``mount`` (or the only one)."""
        if self._clock() >= challenge.expires_at:
            raise ProtocolError("challenge has already expired")
        selected = self._select(mount)
        if not selected.device.is_bindable:
            raise UnsupportedDeviceError(
                f"drive reports no usable serial ({selected.device.serial_quality.value})"
            )
        secret = (
            self._unlock_secret(selected.token.token_id) if selected.token.key_encrypted else None
        )
        key = load_private_key(selected.token, secret)
        report = selected.device.report(selected.volume)
        payload = signing_payload(
            challenge.nonce, challenge.purpose, selected.token.token_id, report
        )
        return Response(
            nonce=challenge.nonce,
            token_id=selected.token.token_id,
            device=report,
            signature=b64url_encode(key.sign(payload)),
        )
