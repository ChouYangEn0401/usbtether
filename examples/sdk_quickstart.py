"""Minimal library usage: guard one operation with a USB-backed capability.

Enroll a drive first (once)::

    usbtether enroll E:

then::

    python examples/sdk_quickstart.py
"""

from __future__ import annotations

from usbtether import (
    Agent,
    AuthorizationError,
    Authorizer,
    DeviceProbe,
    PresenceMonitor,
    Registry,
    UsbTetherError,
    Verifier,
    default_probe,
)


def run(probe: DeviceProbe, registry: Registry) -> str:
    verifier = Verifier(registry)
    authorizer = Authorizer(verifier, capability_ttl=8)
    agent = Agent(probe)

    # 1. One authentication opens a session. The session alone grants nothing.
    session = authorizer.open_session_local(agent)

    # 2. Revoke the session if the drive is unplugged.
    with PresenceMonitor(probe, authorizer, interval=1.0):
        # 3. Every protected operation needs its own fresh challenge-response ...
        capability = authorizer.issue_capability_local(
            agent, session.session_id, resource="database", action="write"
        )
        # 4. ... and spends a single-use, scoped, short-lived capability.
        authorizer.consume(capability, resource="database", action="write")
        return "write performed"


if __name__ == "__main__":
    try:
        print(run(default_probe(), Registry.default()))
    except (UsbTetherError, AuthorizationError) as exc:
        raise SystemExit(f"denied: {exc}") from exc
