"""Wire types for ``usbtether-auth-v1``. See ``docs/protocol.md``."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ._canonical import canonical_json
from .device import DeviceReport
from .errors import ProtocolError

PROTOCOL = "usbtether-auth-v1"
NONCE_BYTES = 32


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError(f"invalid base64url: {exc}") from exc


def new_nonce() -> str:
    return b64url_encode(secrets.token_bytes(NONCE_BYTES))


class FailureReason(str, Enum):
    MALFORMED = "malformed"
    UNKNOWN_CHALLENGE = "unknown_challenge"  # never issued, or already used
    CHALLENGE_EXPIRED = "challenge_expired"
    PURPOSE_MISMATCH = "purpose_mismatch"
    UNKNOWN_TOKEN = "unknown_token"
    TOKEN_REVOKED = "token_revoked"
    DEVICE_UNSUPPORTED = "device_unsupported"  # reported serial is not a real serial
    BAD_SIGNATURE = "bad_signature"
    DEVICE_MISMATCH = "device_mismatch"  # token is valid but this is not the enrolled drive


@dataclass(frozen=True)
class Challenge:
    """Issued by the verifier. Single use, bound to a purpose, expires quickly."""

    nonce: str
    purpose: str
    expires_at: float  # unix time, seconds

    def to_dict(self) -> dict[str, Any]:
        return {"nonce": self.nonce, "purpose": self.purpose, "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Challenge:
        try:
            return cls(str(data["nonce"]), str(data["purpose"]), float(data["expires_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(f"invalid challenge: {exc}") from exc


@dataclass(frozen=True)
class Response:
    """Produced by the agent: a signature over the challenge and the observed device."""

    nonce: str
    token_id: str
    device: DeviceReport
    signature: str  # base64url Ed25519 signature

    def to_dict(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "token_id": self.token_id,
            "device": self.device.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Response:
        try:
            return cls(
                nonce=str(data["nonce"]),
                token_id=str(data["token_id"]),
                device=DeviceReport.from_dict(data["device"]),
                signature=str(data["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(f"invalid response: {exc}") from exc


@dataclass(frozen=True)
class AuthResult:
    """Outcome of verifying one response."""

    ok: bool
    purpose: str | None = None
    token_id: str | None = None
    fingerprint: str | None = None
    reason: FailureReason | None = None
    warnings: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "purpose": self.purpose,
            "token_id": self.token_id,
            "reason": self.reason.value if self.reason else None,
            "warnings": list(self.warnings),
            "detail": self.detail,
        }


def signing_payload(nonce: str, purpose: str, token_id: str, device: DeviceReport) -> bytes:
    """Exact bytes that the token signs and the verifier checks.

    Domain-separated by the protocol identifier and encoded as canonical JSON, so the same
    signature cannot be replayed for another purpose, nonce, token or device claim.
    """
    body = canonical_json(
        {
            "protocol": PROTOCOL,
            "nonce": nonce,
            "purpose": purpose,
            "token_id": token_id,
            "device": device.to_dict(),
        }
    )
    return PROTOCOL.encode("ascii") + b"\n" + body
