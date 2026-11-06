import shutil

import pytest

from usbtether.agent import Agent
from usbtether.device import DeviceReport
from usbtether.enrollment import enroll
from usbtether.errors import (
    AmbiguousDeviceError,
    DeviceNotFoundError,
    ProtocolError,
    TokenLockedError,
    UnsupportedDeviceError,
)
from usbtether.protocol import (
    AuthResult,
    Challenge,
    FailureReason,
    Response,
    b64url_encode,
    signing_payload,
)
from usbtether.token import TOKEN_DIR, load_private_key, read_token
from usbtether.verifier import Verifier

from .conftest import Clock, add_stick


@pytest.fixture
def enrolled(stick, probe, registry, clock):
    device, mount = stick
    enroll(probe, registry, mount)
    verifier = Verifier(registry, clock=clock, challenge_ttl=30)
    agent = Agent(probe, clock=clock)
    return verifier, agent, device, mount


def test_happy_path(enrolled):
    verifier, agent, device, mount = enrolled
    result = verifier.authenticate(agent, "login", mount)
    assert result.ok
    assert result.purpose == "login"
    assert result.fingerprint == device.fingerprint
    assert result.reason is None
    assert result.warnings == ()


def test_agent_autodetects_the_only_enrolled_drive(enrolled):
    verifier, agent, *_ = enrolled
    assert verifier.authenticate(agent, "login").ok


def test_challenge_is_single_use(enrolled):
    verifier, agent, _, mount = enrolled
    challenge = verifier.issue_challenge("login")
    response = agent.respond(challenge, mount)
    assert verifier.verify(response).ok
    replay = verifier.verify(response)
    assert not replay.ok
    assert replay.reason is FailureReason.UNKNOWN_CHALLENGE


def test_forged_nonce_is_rejected(enrolled):
    verifier, agent, _, mount = enrolled
    fake = Challenge("A" * 43, "login", 9e12)
    result = verifier.verify(agent.respond(fake, mount))
    assert result.reason is FailureReason.UNKNOWN_CHALLENGE


def test_expired_challenge(enrolled, probe, clock):
    verifier, _, _, mount = enrolled
    stale_agent = Agent(probe, clock=lambda: 0.0)  # agent with a stale clock
    challenge = verifier.issue_challenge("login")
    response = stale_agent.respond(challenge, mount)
    clock.advance(31)
    assert verifier.verify(response).reason is FailureReason.CHALLENGE_EXPIRED


def test_agent_refuses_expired_challenge(enrolled, clock):
    verifier, agent, _, mount = enrolled
    challenge = verifier.issue_challenge("login")
    clock.advance(31)
    with pytest.raises(ProtocolError):
        agent.respond(challenge, mount)


def test_purpose_is_bound(enrolled):
    verifier, agent, _, mount = enrolled
    response = agent.respond(verifier.issue_challenge("read"), mount)
    result = verifier.verify(response, expected_purpose="write")
    assert result.reason is FailureReason.PURPOSE_MISMATCH


def test_signature_cannot_be_moved_to_another_purpose(enrolled):
    verifier, agent, _, mount = enrolled
    challenge = verifier.issue_challenge("read")
    genuine = agent.respond(challenge, mount)
    # Present the genuine signature as if the challenge had been issued for "write".
    other = verifier.issue_challenge("write")
    forged = Response(other.nonce, genuine.token_id, genuine.device, genuine.signature)
    assert verifier.verify(forged).reason is FailureReason.BAD_SIGNATURE


def test_tampered_device_report_invalidates_signature(enrolled):
    verifier, agent, _, mount = enrolled
    response = agent.respond(verifier.issue_challenge("login"), mount)
    report = response.device.to_dict()
    report["serial"] = "FFEEDDCCBBAA9988"
    forged = Response(
        response.nonce, response.token_id, DeviceReport.from_dict(report), response.signature
    )
    assert verifier.verify(forged).reason is FailureReason.BAD_SIGNATURE


def test_signature_by_a_different_key(enrolled):
    verifier, agent, _, mount = enrolled
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    challenge = verifier.issue_challenge("login")
    genuine = agent.respond(challenge, mount)
    payload = signing_payload(challenge.nonce, "login", genuine.token_id, genuine.device)
    forged = Response(
        genuine.nonce,
        genuine.token_id,
        genuine.device,
        b64url_encode(Ed25519PrivateKey.generate().sign(payload)),
    )
    assert verifier.verify(forged).reason is FailureReason.BAD_SIGNATURE


def test_unknown_and_revoked_tokens(enrolled, registry):
    verifier, agent, _, mount = enrolled
    token_id = read_token(mount).token_id
    registry.revoke(token_id)
    result = verifier.authenticate(agent, "login", mount)
    assert result.reason is FailureReason.TOKEN_REVOKED
    registry.remove(token_id)
    assert verifier.authenticate(agent, "login", mount).reason is FailureReason.UNKNOWN_TOKEN


def test_copy_to_a_different_drive_is_rejected(enrolled, probe, tmp_path):
    """The core claim: files copied to another physical drive do not authenticate."""
    verifier, agent, _, mount = enrolled
    _, clone_mount = add_stick(tmp_path, probe, "clone", "BB99887766554433")
    shutil.copytree(mount / TOKEN_DIR, clone_mount / TOKEN_DIR)
    result = verifier.authenticate(agent, "login", clone_mount)
    assert not result.ok
    assert result.reason is FailureReason.DEVICE_MISMATCH


def test_copy_to_a_drive_without_usable_serial_is_refused_by_agent(enrolled, probe, tmp_path):
    _, agent, _, mount = enrolled
    _, clone_mount = add_stick(tmp_path, probe, "nameless", None)
    shutil.copytree(mount / TOKEN_DIR, clone_mount / TOKEN_DIR)
    with pytest.raises(UnsupportedDeviceError):
        Verifier(enrolled[0].registry).authenticate(agent, "login", clone_mount)


def test_malicious_agent_claiming_no_serial_is_rejected_by_verifier(enrolled):
    verifier, _, device, mount = enrolled
    challenge = verifier.issue_challenge("login")
    key = load_private_key(read_token(mount))
    report = DeviceReport(device.vendor_id, device.product_id, None)
    payload = signing_payload(challenge.nonce, "login", read_token(mount).token_id, report)
    forged = Response(
        challenge.nonce, read_token(mount).token_id, report, b64url_encode(key.sign(payload))
    )
    assert verifier.verify(forged).reason is FailureReason.DEVICE_UNSUPPORTED


def test_spoofed_descriptor_is_accepted_known_limitation(enrolled, probe, tmp_path):
    """KNOWN LIMITATION, asserted so it is never forgotten (docs/threat-model.md).

    A drive that reports the *same* VID/PID/serial as the original, for example one with
    reprogrammed controller firmware, passes. usbtether detects casual copying; it cannot
    prove a drive is the original hardware.
    """
    verifier, agent, device, mount = enrolled
    _, clone_mount = add_stick(tmp_path, probe, "spoof", device.serial)
    shutil.copytree(mount / TOKEN_DIR, clone_mount / TOKEN_DIR)
    assert verifier.authenticate(agent, "login", clone_mount).ok


def test_reformatting_only_produces_warnings(enrolled, probe, tmp_path):
    verifier, agent, device, mount = enrolled
    probe.clear()
    probe.add(
        type(device)(
            vendor_id=device.vendor_id,
            product_id=device.product_id,
            serial=device.serial,
            product=device.product,
            capacity=device.capacity,
            volumes=(
                type(device.volumes[0])(
                    mount_point=str(mount),
                    volume_serial="DEAD-BEEF",
                    filesystem="NTFS",
                    capacity=device.capacity,
                ),
            ),
        )
    )
    result = verifier.authenticate(agent, "login", mount)
    assert result.ok
    assert set(result.warnings) == {"volume_serial_changed", "filesystem_changed"}


def test_pending_challenges_are_bounded(registry, clock):
    verifier = Verifier(registry, clock=clock, max_pending=2)
    first = verifier.issue_challenge("a")
    verifier.issue_challenge("b")
    verifier.issue_challenge("c")
    response = Response(first.nonce, "t", DeviceReport("0781", "5567", "AA00112233445566"), "AA")
    assert verifier.verify(response).reason is FailureReason.UNKNOWN_CHALLENGE


def test_agent_needs_a_drive(probe):
    agent = Agent(probe)
    with pytest.raises(DeviceNotFoundError):
        agent.respond(Challenge("n", "p", 9e12))
    with pytest.raises(DeviceNotFoundError):
        agent.respond(Challenge("n", "p", 9e12), "/nonexistent")


def test_several_enrolled_drives_require_a_choice(enrolled, probe, registry, tmp_path):
    verifier, agent, _, _ = enrolled
    _, second = add_stick(tmp_path, probe, "second", "CC11223344556677")
    enroll(probe, registry, second)
    with pytest.raises(AmbiguousDeviceError):
        verifier.authenticate(agent, "login")
    assert verifier.authenticate(agent, "login", second).ok


def test_passphrase_protected_token(stick, probe, registry, clock):
    _, mount = stick
    enroll(probe, registry, mount, passphrase=b"hunter2")
    verifier = Verifier(registry, clock=clock)
    with pytest.raises(TokenLockedError):
        verifier.authenticate(Agent(probe, clock=clock), "login", mount)
    assert verifier.authenticate(
        Agent(probe, passphrase=b"hunter2", clock=clock), "login", mount
    ).ok
    assert verifier.authenticate(
        Agent(probe, passphrase=lambda: b"hunter2", clock=clock), "login", mount
    ).ok


def test_messages_roundtrip_through_dicts(enrolled):
    verifier, agent, _, mount = enrolled
    challenge = Challenge.from_dict(verifier.issue_challenge("login").to_dict())
    response = Response.from_dict(agent.respond(challenge, mount).to_dict())
    result = verifier.verify(response)
    assert result.ok
    assert isinstance(result, AuthResult)
    assert result.to_dict()["reason"] is None


@pytest.mark.parametrize(
    "bad", [{}, {"nonce": "x"}, {"nonce": "x", "token_id": "t", "device": {}, "signature": "s"}]
)
def test_malformed_response_dicts(bad):
    with pytest.raises(ProtocolError):
        Response.from_dict(bad)


def test_clock_fixture_is_independent():
    assert Clock(5).now == 5


def test_unencrypted_token_never_triggers_the_passphrase_callback(stick, probe, registry, clock):
    _, mount = stick
    enroll(probe, registry, mount)

    def must_not_be_called():
        raise AssertionError("asked for a passphrase although the key is not encrypted")

    agent = Agent(probe, passphrase=must_not_be_called, clock=clock)
    assert Verifier(registry, clock=clock).authenticate(agent, "login", mount).ok


def test_registry_file_can_be_copied_to_another_computer(enrolled, registry, tmp_path, clock):
    """docs/usage.md: one drive on several computers = copy registry.json to each of them."""
    _, agent, _, mount = enrolled
    other_host = tmp_path / "other-pc" / "registry.json"
    other_host.parent.mkdir()
    shutil.copy(registry.path, other_host)

    from usbtether.registry import Registry

    other_verifier = Verifier(Registry(other_host), clock=clock)
    assert other_verifier.authenticate(agent, "login", mount).ok
    # A host that never received the registry does not know the token.
    stranger = Verifier(Registry(tmp_path / "empty.json"), clock=clock)
    assert stranger.authenticate(agent, "login", mount).reason is FailureReason.UNKNOWN_TOKEN
