import shutil
import time
from dataclasses import replace

import pytest

from usbtether.agent import Agent
from usbtether.authz import Authorizer, Capability, capability_purpose
from usbtether.enrollment import enroll
from usbtether.errors import AuthorizationError
from usbtether.monitor import PresenceMonitor
from usbtether.probe.base import DeviceProbe
from usbtether.token import TOKEN_DIR
from usbtether.verifier import Verifier

from .conftest import add_stick


@pytest.fixture
def env(stick, probe, registry, clock):
    device, mount = stick
    enroll(probe, registry, mount)
    verifier = Verifier(registry, clock=clock)
    authorizer = Authorizer(verifier, session_ttl=600, capability_ttl=8, clock=clock)
    agent = Agent(probe, clock=clock)
    return authorizer, agent, device, mount


def reason(excinfo) -> str:
    return excinfo.value.reason


def test_session_and_single_use_capability(env):
    authorizer, agent, device, mount = env
    session = authorizer.open_session_local(agent, mount)
    assert session.fingerprint == device.fingerprint
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "write", mount)
    authorizer.consume(cap, resource="db", action="write")
    with pytest.raises(AuthorizationError) as exc:
        authorizer.consume(cap, resource="db", action="write")
    assert reason(exc) == "capability_used"


def test_a_clone_cannot_open_a_session(env, probe, tmp_path):
    authorizer, agent, _, mount = env
    _, clone = add_stick(tmp_path, probe, "clone", "BB99887766554433")
    shutil.copytree(mount / TOKEN_DIR, clone / TOKEN_DIR)
    with pytest.raises(AuthorizationError) as exc:
        authorizer.open_session_local(agent, clone)
    assert reason(exc) == "device_mismatch"


def test_challenges_are_only_valid_for_the_flow_that_issued_them(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    session_challenge = authorizer.begin_session()
    response = agent.respond(session_challenge, mount)
    with pytest.raises(AuthorizationError) as exc:
        authorizer.complete_capability(response)  # session response used as a capability
    assert reason(exc) == "unknown_challenge"
    # A challenge nobody asked this authorizer for.
    foreign = authorizer.verifier.issue_challenge("session")
    with pytest.raises(AuthorizationError) as exc:
        authorizer.complete_session(agent.respond(foreign, mount))
    assert reason(exc) == "unknown_challenge"
    assert session.session_id


def test_capability_expires(env, clock):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    clock.advance(9)
    with pytest.raises(AuthorizationError) as exc:
        authorizer.consume(cap, resource="db", action="read")
    assert reason(exc) == "capability_expired"


def test_capability_is_scoped(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    for resource, action in [("db", "write"), ("files", "read")]:
        with pytest.raises(AuthorizationError) as exc:
            authorizer.consume(cap, resource=resource, action=action)
        assert reason(exc) == "scope_mismatch"
    authorizer.consume(cap, resource="db", action="read")  # the legitimate use still works


def test_tampered_capability_is_rejected(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    for forged in (
        replace(cap, expires_at=cap.expires_at + 3600),
        replace(cap, max_uses=100),
        replace(cap, action="write"),
        replace(cap, signature="0" * 64),
    ):
        with pytest.raises(AuthorizationError) as exc:
            authorizer.consume(forged, resource=forged.resource, action=forged.action)
        assert reason(exc) == "bad_signature"
    unknown = replace(cap, capability_id="nope")
    with pytest.raises(AuthorizationError) as exc:
        authorizer.consume(unknown, resource="db", action="read")
    assert reason(exc) == "unknown_capability"


def test_capability_roundtrips_through_dict(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    authorizer.consume(Capability.from_dict(cap.to_dict()), resource="db", action="read")
    with pytest.raises(AuthorizationError):
        Capability.from_dict({"capability_id": "x"})


def test_capability_requires_the_session_token(env, probe, registry, tmp_path):
    """A second enrolled drive must not be able to act inside the first drive's session."""
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    _, other = add_stick(tmp_path, probe, "other", "CC11223344556677")
    enroll(probe, registry, other)
    challenge = authorizer.begin_capability(session.session_id, "db", "write")
    with pytest.raises(AuthorizationError) as exc:
        authorizer.complete_capability(agent.respond(challenge, other))
    assert reason(exc) == "token_mismatch"


def test_session_expiry(env, clock):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    clock.advance(601)
    with pytest.raises(AuthorizationError) as exc:
        authorizer.begin_capability(session.session_id, "db", "read")
    assert reason(exc) == "session_inactive"
    assert authorizer.active_sessions() == []


def test_unknown_session(env):
    authorizer, *_ = env
    with pytest.raises(AuthorizationError) as exc:
        authorizer.begin_capability("ghost", "db", "read")
    assert reason(exc) == "unknown_session"


def test_revoking_a_session_kills_outstanding_capabilities(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    authorizer.revoke_session(session.session_id, "admin")
    with pytest.raises(AuthorizationError) as exc:
        authorizer.consume(cap, resource="db", action="read")
    assert reason(exc) == "session_inactive"
    with pytest.raises(AuthorizationError):
        authorizer.begin_capability(session.session_id, "db", "read")


def test_capability_purposes_cannot_collide():
    assert capability_purpose("a:b", "c") != capability_purpose("a", "b:c")


# -- presence monitor -------------------------------------------------------------------


def test_unplugging_revokes_the_session_and_replugging_does_not_revive_it(env, probe, stick):
    authorizer, agent, device, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    revoked = []
    monitor = PresenceMonitor(probe, authorizer, on_revoked=revoked.append)

    assert monitor.check_once() == []  # still plugged in
    probe.remove(device)
    assert [s.session_id for s in monitor.check_once()] == [session.session_id]
    assert revoked and revoked[0].revoked_reason == "device_removed"

    probe.add(device)
    assert monitor.check_once() == []
    assert authorizer.get_session(session.session_id).revoked_reason == "device_removed"
    with pytest.raises(AuthorizationError):
        authorizer.consume(cap, resource="db", action="read")
    # A new session needs a new authentication.
    assert authorizer.open_session_local(agent, mount).session_id != session.session_id


def test_other_drives_do_not_keep_a_session_alive(env, probe, tmp_path):
    authorizer, agent, device, mount = env
    session = authorizer.open_session_local(agent, mount)
    add_stick(tmp_path, probe, "bystander", "DD11223344556677")
    probe.remove(device)
    monitor = PresenceMonitor(probe, authorizer)
    assert [s.session_id for s in monitor.check_once()] == [session.session_id]


def test_transient_probe_failures_are_tolerated_until_the_limit(env, probe):
    from usbtether.errors import ProbeError

    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)

    class Flaky(DeviceProbe):
        def list_devices(self):
            raise ProbeError("powershell timed out")

    monitor = PresenceMonitor(Flaky(), authorizer, max_probe_failures=3)
    assert monitor.check_once() == []
    assert monitor.check_once() == []
    assert authorizer.get_session(session.session_id).revoked_reason is None
    assert len(monitor.check_once()) == 1
    assert authorizer.get_session(session.session_id).revoked_reason == "probe_failed"


def test_background_thread_revokes_on_removal(env, probe):
    authorizer, agent, device, mount = env
    session = authorizer.open_session_local(agent, mount)
    with PresenceMonitor(probe, authorizer, interval=0.01):
        probe.remove(device)
        deadline = time.time() + 5
        while (
            time.time() < deadline
            and authorizer.get_session(session.session_id).revoked_reason is None
        ):
            time.sleep(0.01)
    assert authorizer.get_session(session.session_id).revoked_reason == "device_removed"


def test_signed_capability_payload_has_no_floats(env):
    authorizer, agent, _, mount = env
    session = authorizer.open_session_local(agent, mount)
    cap = authorizer.issue_capability_local(agent, session.session_id, "db", "read", mount)
    payload = cap.payload()
    assert all(not isinstance(v, float) for v in payload.values())
    assert isinstance(payload["expires_at_ms"], int)
    assert Capability.from_dict(cap.to_dict()) == cap
