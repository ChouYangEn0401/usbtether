"""Sessions and short-lived, single-use capabilities on top of authentication.

* A **session** is opened by one successful authentication. It carries no authority by
  itself.
* A **capability** grants exactly one use of one ``(resource, action)`` pair for a few
  seconds, and is issued only after a *fresh* challenge-response with the same token.
* Revoking a session (for example because the drive was unplugged) invalidates every
  capability issued under it.

State is held in memory and is lost on restart, which is the safe direction.
"""

from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal

from ._canonical import canonical_json
from .errors import AuthorizationError
from .protocol import Challenge, Response
from .verifier import Verifier

if TYPE_CHECKING:
    from .agent import Agent

SESSION_PURPOSE = "session"


def capability_purpose(resource: str, action: str) -> str:
    """Unambiguous challenge purpose for a ``(resource, action)`` pair."""
    return "capability:" + canonical_json([resource, action]).decode("ascii")


@dataclass
class Session:
    session_id: str
    token_id: str
    fingerprint: str
    created_at: float
    expires_at: float
    revoked_reason: str | None = None

    def is_active(self, now: float) -> bool:
        return self.revoked_reason is None and now < self.expires_at


@dataclass(frozen=True)
class Capability:
    capability_id: str
    session_id: str
    resource: str
    action: str
    expires_at: float
    max_uses: int
    signature: str

    def payload(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "session_id": self.session_id,
            "resource": self.resource,
            "action": self.action,
            # Integer milliseconds: signed payloads must not contain floats.
            "expires_at_ms": round(self.expires_at * 1000),
            "max_uses": self.max_uses,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        try:
            return cls(
                capability_id=str(data["capability_id"]),
                session_id=str(data["session_id"]),
                resource=str(data["resource"]),
                action=str(data["action"]),
                expires_at=int(data["expires_at_ms"]) / 1000,
                max_uses=int(data["max_uses"]),
                signature=str(data["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationError("malformed_capability", str(exc)) from exc


@dataclass
class _Pending:
    kind: Literal["session", "capability"]
    expires_at: float
    session_id: str | None = None
    resource: str | None = None
    action: str | None = None


@dataclass
class _Issued:
    capability: Capability
    uses: int = 0


@dataclass
class Authorizer:
    verifier: Verifier
    session_ttl: float = 3600.0
    capability_ttl: float = 8.0
    clock: Callable[[], float] = time.time
    _key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    _sessions: dict[str, Session] = field(default_factory=dict, repr=False)
    _pending: dict[str, _Pending] = field(default_factory=dict, repr=False)
    _issued: dict[str, _Issued] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # -- sessions ---------------------------------------------------------------------

    def begin_session(self) -> Challenge:
        challenge = self.verifier.issue_challenge(SESSION_PURPOSE)
        self._remember(challenge, _Pending("session", challenge.expires_at))
        return challenge

    def complete_session(self, response: Response) -> Session:
        self._take(response.nonce, "session")
        result = self.verifier.verify(response, expected_purpose=SESSION_PURPOSE)
        if not result.ok or result.token_id is None or result.fingerprint is None:
            reason = result.reason.value if result.reason else "failed"
            raise AuthorizationError(reason, result.detail or reason)
        now = self.clock()
        session = Session(
            session_id=secrets.token_urlsafe(18),
            token_id=result.token_id,
            fingerprint=result.fingerprint,
            created_at=now,
            expires_at=now + self.session_ttl,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def active_sessions(self) -> list[Session]:
        now = self.clock()
        with self._lock:
            return [s for s in self._sessions.values() if s.is_active(now)]

    def revoke_session(self, session_id: str, reason: str = "revoked") -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None and session.revoked_reason is None:
                session.revoked_reason = reason

    # -- capabilities -----------------------------------------------------------------

    def begin_capability(self, session_id: str, resource: str, action: str) -> Challenge:
        self._require_active(session_id)
        challenge = self.verifier.issue_challenge(capability_purpose(resource, action))
        self._remember(
            challenge,
            _Pending("capability", challenge.expires_at, session_id, resource, action),
        )
        return challenge

    def complete_capability(self, response: Response) -> Capability:
        pending = self._take(response.nonce, "capability")
        assert pending.session_id and pending.resource and pending.action  # set by begin_*
        session = self._require_active(pending.session_id)
        purpose = capability_purpose(pending.resource, pending.action)
        result = self.verifier.verify(response, expected_purpose=purpose)
        if not result.ok:
            reason = result.reason.value if result.reason else "failed"
            raise AuthorizationError(reason, result.detail or reason)
        if result.token_id != session.token_id:
            raise AuthorizationError("token_mismatch", "response is from a different token")
        session = self._require_active(session.session_id)  # may have been revoked meanwhile
        unsigned = Capability(
            capability_id=secrets.token_urlsafe(16),
            session_id=session.session_id,
            resource=pending.resource,
            action=pending.action,
            expires_at=round((self.clock() + self.capability_ttl) * 1000) / 1000,
            max_uses=1,
            signature="",
        )
        capability = replace(unsigned, signature=self._sign(unsigned))
        with self._lock:
            self._issued[capability.capability_id] = _Issued(capability)
        return capability

    def consume(self, capability: Capability, *, resource: str, action: str) -> None:
        """Spend one use of ``capability`` for ``(resource, action)`` or raise."""
        with self._lock:
            issued = self._issued.get(capability.capability_id)
            if issued is None:
                raise AuthorizationError("unknown_capability")
            if not hmac.compare_digest(capability.signature, self._sign(capability)):
                raise AuthorizationError("bad_signature")
            if capability != issued.capability:
                raise AuthorizationError("bad_signature", "capability does not match issued one")
            if (capability.resource, capability.action) != (resource, action):
                raise AuthorizationError("scope_mismatch")
            if self.clock() >= capability.expires_at:
                raise AuthorizationError("capability_expired")
            if issued.uses >= capability.max_uses:
                raise AuthorizationError("capability_used")
            self._require_active(capability.session_id)
            issued.uses += 1

    # -- convenience for single-process use ------------------------------------------

    def open_session_local(
        self, agent: Agent, mount: str | os.PathLike[str] | None = None
    ) -> Session:
        return self.complete_session(agent.respond(self.begin_session(), mount))

    def issue_capability_local(
        self,
        agent: Agent,
        session_id: str,
        resource: str,
        action: str,
        mount: str | os.PathLike[str] | None = None,
    ) -> Capability:
        challenge = self.begin_capability(session_id, resource, action)
        return self.complete_capability(agent.respond(challenge, mount))

    # -- internals --------------------------------------------------------------------

    def _sign(self, capability: Capability) -> str:
        return hmac.new(self._key, canonical_json(capability.payload()), sha256).hexdigest()

    def _remember(self, challenge: Challenge, pending: _Pending) -> None:
        now = self.clock()
        with self._lock:
            for nonce in [n for n, p in self._pending.items() if p.expires_at <= now]:
                del self._pending[nonce]
            for cid in [c for c, i in self._issued.items() if i.capability.expires_at < now - 60]:
                del self._issued[cid]
            self._pending[challenge.nonce] = pending

    def _take(self, nonce: str, kind: str) -> _Pending:
        with self._lock:
            pending = self._pending.pop(nonce, None)
        if pending is None or pending.kind != kind:
            raise AuthorizationError("unknown_challenge", "challenge unknown or already used")
        return pending

    def _require_active(self, session_id: str) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise AuthorizationError("unknown_session")
            if not session.is_active(self.clock()):
                raise AuthorizationError("session_inactive", session.revoked_reason or "expired")
            return session
