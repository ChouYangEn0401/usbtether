import json
import os
import secrets
import shutil
import threading
import time

import pytest

from usbtether.errors import UsbTetherError
from usbtether.opener import BoundFolders, open_encrypted, protect_folder, sweep
from usbtether.vault import decrypt_file, encrypt_file

KEY = secrets.token_bytes(32)


def _encrypted(tmp_path, data=b"draft 1"):
    plain = tmp_path / "docs" / "note.txt"
    plain.parent.mkdir(parents=True)
    plain.write_bytes(data)
    return encrypt_file(plain, KEY)


def test_open_syncs_saves_back_and_cleans_up_when_the_drive_leaves(tmp_path):
    source = _encrypted(tmp_path)
    home = tmp_path / "home"
    opened, plugged = [], threading.Event()
    plugged.set()

    def fake_editor(path):
        opened.append(path)

    t = threading.Thread(
        target=open_encrypted,
        args=(source, KEY, home),
        kwargs={"present": plugged.is_set, "open_file": fake_editor, "poll": 0.05},
    )
    t.start()
    deadline = time.time() + 5
    while not opened and time.time() < deadline:
        time.sleep(0.02)
    work = opened[0]
    assert work.read_bytes() == b"draft 1" and home in work.parents
    assert not (tmp_path / "docs" / "note.txt").exists()  # the visible folder stays encrypted

    work.write_bytes(b"draft 2")  # the user saves
    os.utime(work, (time.time() - 5, time.time() - 5))
    deadline = time.time() + 5
    while time.time() < deadline:
        check = tmp_path / "check"
        check.mkdir(exist_ok=True)
        if decrypt_file(source, KEY, dest_dir=check, keep=True).read_bytes() == b"draft 2":
            break
        time.sleep(0.05)
    else:
        pytest.fail("save was not encrypted back")

    plugged.clear()  # pull the drive out
    t.join(5)
    assert not t.is_alive() and not work.exists()
    assert source.exists()


def test_unsaved_change_is_synced_back_when_the_drive_leaves(tmp_path):
    source = _encrypted(tmp_path)
    calls = {"n": 0}

    def present():
        calls["n"] += 1
        return calls["n"] < 3

    def editor(path):
        path.write_bytes(b"edited")  # saved just before the drive goes away

    open_encrypted(source, KEY, tmp_path / "home", present=present, open_file=editor, poll=0.01)
    out = decrypt_file(source, KEY, dest_dir=tmp_path / "out", keep=True)
    assert out.read_bytes() == b"edited"


def test_open_rejects_plain_files(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"x")
    with pytest.raises(UsbTetherError):
        open_encrypted(f, KEY, tmp_path, present=lambda: True, open_file=lambda _: None)


def test_sweep_recovers_after_a_killed_helper(tmp_path):
    source = _encrypted(tmp_path)
    home = tmp_path / "home"

    class Killed(Exception):
        pass

    def editor(path):
        path.write_bytes(b"unsaved work")
        os.utime(path, (time.time() - 60, time.time() - 60))
        raise Killed  # the helper dies right after opening

    with pytest.raises(Killed):
        open_encrypted(source, KEY, home, present=lambda: True, open_file=editor)
    # the helper's finally ran here, but simulate a hard kill: rebuild a stale slot
    slot = home / "open" / "stale"
    slot.mkdir(parents=True)
    (slot / "note.txt").write_bytes(b"left behind")
    (slot / ".state").write_text(json.dumps({"src": str(source), "synced": ""}))
    (slot / ".lock").write_text("1")
    os.utime(slot / ".lock", (1, 1))

    assert sweep(home, None) == 0 and slot.exists()  # no key: keep it, nothing lost
    assert sweep(home, KEY) == 1 and not slot.exists()
    out = decrypt_file(source, KEY, dest_dir=tmp_path / "out", keep=True)
    assert out.read_bytes() == b"left behind"


def test_bound_folders_and_protect(tmp_path):
    store = BoundFolders(tmp_path / "home")
    folder = tmp_path / "b"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "a.txt").write_bytes(b"a")
    (folder / "fresh.txt").write_bytes(b"f")
    os.utime(folder / "sub" / "a.txt", (1, 1))
    store.add(folder)
    store.add(folder)
    assert store.folders() == [folder.resolve()]
    assert protect_folder(folder, KEY) == 1  # fresh.txt is still inside the quiet window
    assert (folder / "sub" / "a.txt.utenc").exists() and (folder / "fresh.txt").exists()
    assert protect_folder(folder, KEY, quiet_seconds=0) == 1
    store.remove(folder)
    assert store.folders() == []


def test_encrypt_to_another_folder_keeping_the_source(tmp_path):
    plain = tmp_path / "a.txt"
    plain.write_bytes(b"x")
    out = encrypt_file(plain, KEY, dest_dir=tmp_path / "out", keep=True)
    assert plain.exists() and out == tmp_path / "out" / "a.txt.utenc"
    back = decrypt_file(out, KEY, dest_dir=tmp_path / "back")
    assert back.read_bytes() == b"x" and not out.exists()


def test_folder_guard_follows_the_drive(stick, probe, registry, tmp_path):
    from usbtether.agent import Agent
    from usbtether.enrollment import enroll
    from usbtether.opener import FolderGuard
    from usbtether.token import TOKEN_DIR
    from usbtether.verifier import Verifier

    device, mount = stick
    events = []
    guard = FolderGuard(Agent(probe), Verifier(registry), tmp_path / "home", on_event=events.append)
    guard.step()
    assert guard.status == "waiting" and guard.key is None  # plugged in but not enrolled

    enroll(probe, registry, mount)
    folder = tmp_path / "bound"
    folder.mkdir()
    (folder / "old.txt").write_bytes(b"x")
    os.utime(folder / "old.txt", (1, 1))
    guard.bound.add(folder)
    assert guard.step() == 1 and guard.status == "unlocked" and guard.mount == str(mount)
    assert (folder / "old.txt.utenc").exists()

    guard.bound.auto = False
    (folder / "new.txt").write_bytes(b"y")
    os.utime(folder / "new.txt", (1, 1))
    assert guard.step() == 0 and (folder / "new.txt").exists()
    assert guard.protect_all() == 1  # manual "Encrypt now"

    probe.remove(device)  # unplug: the token folder disappears with the drive
    shutil.move(str(mount / TOKEN_DIR), str(tmp_path / "away"))
    guard.step()
    assert guard.key is None and guard.status == "waiting"
    assert any("removed" in e for e in events)
    with pytest.raises(UsbTetherError):
        guard.ensure_key()
