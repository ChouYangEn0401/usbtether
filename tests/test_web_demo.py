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
