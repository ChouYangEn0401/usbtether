import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import contextlib

from fastapi.testclient import TestClient

from usbtether.enrollment import enroll
from usbtether.token import TOKEN_DIR

from .conftest import add_stick

APP_PATH = Path(__file__).resolve().parents[1] / "examples" / "web_demo" / "app.py"


TEST_CLASSES = r"Software\usbtether-test\Classes"


def load_demo():
    spec = importlib.util.spec_from_file_location("usbtether_web_demo", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # pydantic resolves annotations through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo(stick, probe, registry, tmp_path):
    _, mount = stick
    launched = []
    app = load_demo().create_app(
        probe,
        registry,
        monitor_interval=None,
        assoc_classes=TEST_CLASSES,
        launcher=launched.append,
        search_roots=[tmp_path],
    )
    app.state.launched = launched
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


def test_encrypt_and_decrypt_anywhere(demo, tmp_path):
    client, _, mount = demo
    client.post("/api/usb/enroll", json={"mount": str(mount)})
    src = tmp_path / "docs"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"one")
    (src / "sub" / "b.txt").write_bytes(b"two")

    # in place, keeping the original
    r = client.post("/api/crypt/encrypt", json={"paths": [str(src / "a.txt")]}).json()
    assert r["ok"] and (src / "a.txt").exists() and (src / "a.txt.utenc").exists()

    # a folder to another place, deleting the originals
    out = tmp_path / "out"
    r = client.post(
        "/api/crypt/encrypt",
        json={
            "paths": [str(src / "sub")],
            "delete_source": True,
            "dest": "custom",
            "dest_dir": str(out),
        },
    ).json()
    assert r["ok"] and not (src / "sub" / "b.txt").exists()
    assert (out / "sub" / "b.txt.utenc").is_file()

    back = tmp_path / "back"
    r = client.post(
        "/api/crypt/decrypt",
        json={
            "paths": [str(out / "sub" / "b.txt.utenc")],
            "delete_source": True,
            "dest": "custom",
            "dest_dir": str(back),
        },
    ).json()
    assert r["ok"] and (back / "b.txt").read_bytes() == b"two"
    assert (
        client.post("/api/crypt/encrypt", json={"paths": [str(tmp_path / "nope")]}).json()["ok"]
        is False
    )


def test_dropped_items_are_found_on_disk(demo, tmp_path):
    client, _, _ = demo
    (tmp_path / "Desktop" / "proj").mkdir(parents=True)
    f = tmp_path / "Desktop" / "note.txt"
    f.write_bytes(b"hello")
    items = [
        {"name": "note.txt", "size": 5, "mtime": f.stat().st_mtime * 1000},
        {"name": "proj", "dir": True},
        {"name": "note.txt", "size": 999},  # wrong size: not this file
        {"name": "ghost.txt"},
    ]
    r = client.post("/api/crypt/resolve", json={"items": items}).json()
    assert r["paths"] == [str(f), str(tmp_path / "Desktop" / "proj")]
    assert r["missing"] == ["note.txt", "ghost.txt"]


def test_bound_folder_stays_encrypted(demo, stick, tmp_path):
    client, app, mount = demo
    device, _ = stick
    folder = tmp_path / "bound"
    folder.mkdir()
    (folder / "a.txt").write_bytes(b"one")
    # without an enrolled drive the folder is bound but cannot be encrypted yet
    r = client.post("/api/bind/add", json={"path": str(folder)}).json()
    assert r["ok"] and "Not encrypted yet" in r["message"]
    client.post("/api/usb/enroll", json={"mount": str(mount)})
    app.state.bind_check()
    assert client.post("/api/bind/protect", json={"path": str(folder)}).json()["ok"]
    state = client.get("/api/bind").json()
    assert state["drive"] and [f["name"] for f in state["folders"][0]["files"]] == ["a.txt.utenc"]

    enc = folder / "a.txt.utenc"
    assert client.post("/api/bind/open", json={"path": str(enc)}).json()["ok"]
    assert app.state.launched[-1][-2:] == ["open", str(enc)]

    app.state.monitor._probe.remove(device)  # unplug: the drive's files vanish too
    shutil.move(str(mount / TOKEN_DIR), str(tmp_path / "unplugged"))
    app.state.bind_check()
    assert client.get("/api/bind").json()["drive"] is False

    assert client.post("/api/bind/remove", json={"path": str(folder)}).json()["ok"]
    assert client.get("/api/bind").json()["folders"] == []


def test_manual_mode_leaves_new_files_alone(demo, tmp_path):
    client, app, mount = demo
    client.post("/api/usb/enroll", json={"mount": str(mount)})
    folder = tmp_path / "bound"
    folder.mkdir()
    client.post("/api/bind/auto", json={"auto": False})
    client.post("/api/bind/add", json={"path": str(folder)})
    (folder / "new.txt").write_bytes(b"x")
    os.utime(folder / "new.txt", (1, 1))  # old enough for the quiet window
    app.state.bind_check()
    assert (folder / "new.txt").exists()
    client.post("/api/bind/auto", json={"auto": True})
    app.state.bind_check()
    assert (folder / "new.txt.utenc").exists() and not (folder / "new.txt").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")
def test_register_file_association_in_a_scratch_key(demo):
    client, _, _ = demo
    try:
        assert client.post("/api/bind/register").json()["ok"]
        command = client.get("/api/bind").json()["association"]
        assert command and command.endswith('open "%1"')
        assert client.post("/api/bind/unregister").json()["ok"]
        assert client.get("/api/bind").json()["association"] is None
    finally:
        import winreg

        for sub in (TEST_CLASSES, TEST_CLASSES.rsplit("\\", 1)[0]):
            with contextlib.suppress(OSError):
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
