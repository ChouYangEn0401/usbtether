import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from usbtether.enrollment import enroll
from usbtether.token import TOKEN_DIR

from .conftest import add_stick

APP_PATH = Path(__file__).resolve().parents[1] / "examples" / "web_demo" / "app.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("usbtether_web_demo", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # pydantic resolves annotations through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo(stick, probe, registry):
    _, mount = stick
    app = load_demo().create_app(probe, registry, monitor_interval=None)
    return TestClient(app), app, mount


@pytest.fixture
def enrolled_demo(demo, probe, registry):
    client, app, mount = demo
    enroll(probe, registry, mount)
    return client, app, mount


def run_step(client, session_id, step):
    a = client.post("/api/guard/authorize", json={"session_id": session_id, "step": step}).json()
    assert a["authorized"], a
    return a, client.post(
        "/api/guard/consume",
        json={"session_id": session_id, "step": step, "capability": a["capability"]},
    )


def test_index_is_served(demo):
    client, *_ = demo
    assert "usbtether demo" in client.get("/").text


def test_status_reports_enrollment(demo, probe, registry):
    client, _, mount = demo
    before = client.get("/api/status").json()
    assert before["devices"][0]["bindable"] and not before["ready"]
    enroll(probe, registry, mount)
    assert client.get("/api/status").json()["ready"]


def test_guard_refuses_to_start_without_an_enrolled_drive(demo):
    client, *_ = demo
    result = client.post("/api/guard/start", json={"total_steps": 3}).json()
    assert result["started"] is False


def test_guard_full_workflow(enrolled_demo):
    client, *_ = enrolled_demo
    start = client.post("/api/guard/start", json={"total_steps": 3}).json()
    assert start["started"]
    for step in (1, 2, 3):
        _, consumed = run_step(client, start["session_id"], step)
        assert consumed.json()["remaining_steps"] == 3 - step
    assert (
        client.post(
            "/api/guard/authorize", json={"session_id": start["session_id"], "step": 4}
        ).status_code
        == 409
    )


def test_capability_cannot_be_replayed_or_moved_between_steps(enrolled_demo):
    client, *_ = enrolled_demo
    sid = client.post("/api/guard/start", json={"total_steps": 3}).json()["session_id"]
    first, consumed = run_step(client, sid, 1)
    assert consumed.status_code == 200
    replay = client.post(
        "/api/guard/consume", json={"session_id": sid, "step": 2, "capability": first["capability"]}
    )
    assert replay.status_code in (403, 409)
    second = client.post("/api/guard/authorize", json={"session_id": sid, "step": 2}).json()
    wrong_step = client.post(
        "/api/guard/consume", json={"session_id": sid, "step": 2, "capability": first["capability"]}
    )
    assert wrong_step.status_code in (403, 409)
    assert second["authorized"]


def test_unplugging_mid_workflow_stops_it(enrolled_demo, stick):
    client, app, _ = enrolled_demo
    device, _ = stick
    sid = client.post("/api/guard/start", json={"total_steps": 3}).json()["session_id"]
    run_step(client, sid, 1)
    # Remove the drive and let the presence monitor notice.
    app.state.monitor._probe.remove(device)
    app.state.monitor.check_once()
    result = client.post("/api/guard/authorize", json={"session_id": sid, "step": 2}).json()
    assert result["authorized"] is False


def test_vault_puzzle(demo):
    client, *_ = demo
    ch = client.post("/api/vault/new").json()
    wrong = client.post("/api/vault/solve", json={"challenge_id": ch["challenge_id"], "answer": -1})
    assert wrong.json()["unlocked"] is False
    answer = (ch["x"] * 7 + 13) % 97
    right = client.post(
        "/api/vault/solve", json={"challenge_id": ch["challenge_id"], "answer": answer}
    )
    assert right.json()["unlocked"] is True
    again = client.post(
        "/api/vault/solve", json={"challenge_id": ch["challenge_id"], "answer": answer}
    )
    assert again.status_code == 410


def test_vault_usb_override(enrolled_demo):
    client, *_ = enrolled_demo
    ch = client.post("/api/vault/new").json()
    result = client.post("/api/vault/usb", json={"challenge_id": ch["challenge_id"]}).json()
    assert result["unlocked"] is True
    assert (
        client.post("/api/vault/usb", json={"challenge_id": ch["challenge_id"]}).status_code == 410
    )


def test_vault_usb_override_rejects_a_copied_token(demo, probe, registry, tmp_path):
    client, _, mount = demo
    enroll(probe, registry, mount)
    # Replace the genuine drive by a clone carrying a copy of the token.
    original = probe.list_devices()[0]
    _, clone = add_stick(tmp_path, probe, "clone", "FF00112233445566")
    shutil.copytree(mount / TOKEN_DIR, clone / TOKEN_DIR)
    probe.remove(original)
    ch = client.post("/api/vault/new").json()
    result = client.post("/api/vault/usb", json={"challenge_id": ch["challenge_id"]}).json()
    assert result["unlocked"] is False
    assert "device_mismatch" in result["message"]


def test_demo_works_with_a_remembered_key_and_no_environment_variable(demo, probe, registry):
    """The reported problem: a protected key made the demo unusable. --remember fixes it."""
    client, _, mount = demo
    enroll(probe, registry, mount, remember=True)
    start = client.post("/api/guard/start", json={"total_steps": 2}).json()
    assert start["started"], start
    _, consumed = run_step(client, start["session_id"], 1)
    assert consumed.status_code == 200


def test_demo_explains_how_to_fix_a_locked_key(demo, probe, registry):
    client, _, mount = demo
    enroll(probe, registry, mount, passphrase=b"typed")
    result = client.post("/api/guard/start", json={"total_steps": 2}).json()
    assert result["started"] is False
    assert "--remember" in result["reason"] and "USBTETHER_PASSPHRASE" in result["reason"]


def test_enroll_and_verify_from_the_page(demo):
    client, _, mount = demo
    assert client.post("/api/usb/verify", json={}).json()["ok"] is False  # nothing enrolled yet
    enrolled = client.post("/api/usb/enroll", json={"mount": str(mount)}).json()
    assert enrolled["ok"], enrolled
    assert enrolled["protection"] == "host-secret"
    assert client.post("/api/usb/verify", json={"mount": str(mount)}).json()["ok"] is True
    assert client.get("/api/status").json()["ready"]


def test_enroll_twice_needs_force(demo):
    client, _, mount = demo
    assert client.post("/api/usb/enroll", json={"mount": str(mount)}).json()["ok"]
    again = client.post("/api/usb/enroll", json={"mount": str(mount)}).json()
    assert again["ok"] is False and again["already"] is True
    forced = client.post("/api/usb/enroll", json={"mount": str(mount), "force": True}).json()
    assert forced["ok"] and len(forced["revoked"]) == 1


def test_file_vault_follows_the_drive(demo, stick):
    client, app, mount = demo
    device, _ = stick
    assert client.post("/api/usb/enroll", json={"mount": str(mount)}).json()["ok"]
    assert client.post("/api/box/unlock").json()["ok"]
    put = client.put("/api/box/file", params={"name": "docs/a.txt"}, content=b"top secret")
    assert put.json()["ok"]
    files = client.get("/api/box").json()["files"]
    assert files == [{"name": "docs/a.txt", "size": 10, "encrypted": False}]
    assert client.get("/api/box/file", params={"name": "docs/a.txt"}).content == b"top secret"

    app.state.monitor._probe.remove(device)  # pull the drive out
    app.state.box_check()
    state = client.get("/api/box").json()
    assert state["unlocked"] is False and state["files"][0]["encrypted"] is True
    assert client.get("/api/box/file", params={"name": "docs/a.txt"}).status_code == 403

    app.state.monitor._probe.add(device)  # and back in
    app.state.box_check()
    assert client.get("/api/box").json()["unlocked"] is True
    assert client.get("/api/box/file", params={"name": "docs/a.txt"}).content == b"top secret"


def test_file_vault_rejects_path_escape_and_needs_the_drive(demo):
    client, _, mount = demo
    assert client.put("/api/box/file", params={"name": "../x"}, content=b"x").status_code == 400
    assert client.put("/api/box/file", params={"name": "a.txt"}, content=b"x").json()["ok"] is False
    client.post("/api/usb/enroll", json={"mount": str(mount)})
    assert client.put("/api/box/file", params={"name": "a.txt"}, content=b"x").json()["ok"]
    assert client.get("/api/box").json()["files"][0]["encrypted"] is True  # box was locked
