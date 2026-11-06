"""The verifier owns the registry and decides whether a response is acceptable."""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .device import SerialQuality, advisory_warnings
from .errors import ProtocolError
from .protocol import (
    AuthResult,
    Challenge,
    FailureReason,
    Response,
    b64url_decode,
    new_nonce,
    signing_payload,
)
from .registry import Registry

if TYPE_CHECKING:
    from .agent import Agent


def _fail(
    reason: FailureReason,
    detail: str = "",
    *,
    purpose: str | None = None,
    token_id: str | None = None,
) -> AuthResult:
    return AuthResult(False, purpose=purpose, token_id=token_id, reason=reason, detail=detail)


class Verifier:
    """Issues single-use challenges and verifies responses against the registry.

    Verification succeeds only if **all** of these hold: the challenge is known, unused,
    unexpired and issued for the expected purpose; the token is registered and not revoked;
    the reported serial is a real serial; the Ed25519 signature is valid; and the reported
    drive matches the drive the token was enrolled on.
    """

    def __init__(
        self,
        registry: Registry,
        *,
        challenge_ttl: float = 30.0,
        max_pending: int = 1024,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.registry = registry
        self._ttl = challenge_ttl
        self._max_pending = max_pending
        self._clock = clock
        self._pending: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()

    def issue_challenge(self, purpose: str) -> Challenge:
        now = self._clock()
        challenge = Challenge(new_nonce(), purpose, now + self._ttl)
        with self._lock:
            for nonce in [n for n, (_, exp) in self._pending.items() if exp <= now]:
                del self._pending[nonce]
            while len(self._pending) >= self._max_pending:
                self._pending.popitem(last=False)
            self._pending[challenge.nonce] = (purpose, challenge.expires_at)
        return challenge

    def verify(self, response: Response, *, expected_purpose: str | None = None) -> AuthResult:
        # The challenge is consumed first and unconditionally: one guess per challenge.
        with self._lock:
            pending = self._pending.pop(response.nonce, None)
        if pending is None:
            return _fail(FailureReason.UNKNOWN_CHALLENGE, "challenge unknown or already used")
        purpose, expires_at = pending
        if self._clock() >= expires_at:
            return _fail(FailureReason.CHALLENGE_EXPIRED, purpose=purpose)
        if expected_purpose is not None and expected_purpose != purpose:
            return _fail(FailureReason.PURPOSE_MISMATCH, purpose=purpose)

        entry = self.registry.get(response.token_id)
        if entry is None:
            return _fail(FailureReason.UNKNOWN_TOKEN, purpose=purpose)
        if not entry.is_active:
            return _fail(FailureReason.TOKEN_REVOKED, purpose=purpose, token_id=entry.token_id)

        report = response.device
        if report.serial_quality is not SerialQuality.GOOD:
            return _fail(
                FailureReason.DEVICE_UNSUPPORTED,
                f"serial quality: {report.serial_quality.value}",
                purpose=purpose,
                token_id=entry.token_id,
            )

        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry.public_key))
            public_key.verify(
                b64url_decode(response.signature),
                signing_payload(response.nonce, purpose, entry.token_id, report),
            )
        except (InvalidSignature, ValueError, binascii.Error, ProtocolError):
            return _fail(FailureReason.BAD_SIGNATURE, purpose=purpose, token_id=entry.token_id)

        fingerprint = report.fingerprint()
        if not hmac.compare_digest(fingerprint, entry.fingerprint):
            return _fail(
                FailureReason.DEVICE_MISMATCH,
                "the token is valid but it is not on the drive it was enrolled on",
                purpose=purpose,
                token_id=entry.token_id,
            )

        return AuthResult(
            True,
            purpose=purpose,
            token_id=entry.token_id,
            fingerprint=fingerprint,
            warnings=tuple(advisory_warnings(entry.device, report)),
        )

    def authenticate(
        self, agent: Agent, purpose: str, mount: str | os.PathLike[str] | None = None
    ) -> AuthResult:
        """Run the full exchange when verifier and agent live in the same process."""
        challenge = self.issue_challenge(purpose)
        return self.verify(agent.respond(challenge, mount), expected_purpose=purpose)
