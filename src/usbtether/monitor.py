"""Presence monitor: revoke sessions when the drive that opened them disappears.

This polls the probe. It is not event-driven, so there is a window of up to ``interval``
seconds between removal and revocation. Capabilities are short-lived and are re-checked
against the session when consumed, which bounds the exposure further.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from types import TracebackType

from .authz import Authorizer, Session
from .errors import ProbeError
from .probe.base import DeviceProbe

logger = logging.getLogger("usbtether")


class PresenceMonitor:
    def __init__(
        self,
        probe: DeviceProbe,
        authorizer: Authorizer,
        *,
        interval: float = 1.0,
        max_probe_failures: int = 3,
        on_revoked: Callable[[Session], None] | None = None,
    ) -> None:
        self._probe = probe
        self._authorizer = authorizer
        self._interval = interval
        self._max_failures = max_probe_failures
        self._on_revoked = on_revoked
        self._failures = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def check_once(self) -> list[Session]:
        """Run one check and return the sessions revoked by it."""
        sessions = self._authorizer.active_sessions()
        if not sessions:
            self._failures = 0
            return []
        try:
            devices = self._probe.list_devices()
        except ProbeError as exc:
            self._failures += 1
            logger.warning("USB probe failed (%d/%d): %s", self._failures, self._max_failures, exc)
            if self._failures < self._max_failures:
                return []
            return self._revoke(sessions, "probe_failed")
        self._failures = 0
        present = {d.fingerprint for d in devices if d.is_bindable}
        return self._revoke([s for s in sessions if s.fingerprint not in present], "device_removed")

    def _revoke(self, sessions: list[Session], reason: str) -> list[Session]:
        for session in sessions:
            self._authorizer.revoke_session(session.session_id, reason)
            logger.info("session %s revoked: %s", session.session_id[:8], reason)
            if self._on_revoked is not None:
                self._on_revoked(session)
        return sessions

    # -- background thread ------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="usbtether-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 5)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.check_once()
            except Exception:
                logger.exception("presence check failed")

    def __enter__(self) -> PresenceMonitor:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
