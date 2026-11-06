import json
import shutil

import pytest

from usbtether.cli import main
from usbtether.errors import UnsupportedPlatformError
from usbtether.probe.memory import InMemoryProbe
from usbtether.token import TOKEN_DIR

from .conftest import add_stick


@pytest.fixture
def run(probe, tmp_path, capsys):
    home = tmp_path / "home"

    def _run(*argv):
        code = main(["--home", str(home), *argv], probe=probe)
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def test_devices_text_and_json(run, stick):
    _, mount = stick
    code, out, _ = run("devices")
    assert code == 0
    assert "0781:5567" in out and "bindable : yes" in out and str(mount) in out
    code, out, _ = run("devices", "--json")
    (device,) = json.loads(out)
    assert device["bindable"] is True
    assert device["serial"] == "AA00112233445566"


def test_devices_redaction(run):
    _, out, _ = run("devices", "--json", "--redact")
    (device,) = json.loads(out)
    assert device["serial"] == "AA************66"
    assert device["volumes"][0]["volume_serial"] is None


def test_devices_empty(capsys, tmp_path):
    code = main(["--home", str(tmp_path), "devices"], probe=InMemoryProbe())
    assert code == 0
    assert "No USB" in capsys.readouterr().out


def test_unbindable_device_is_flagged(tmp_path, capsys):
    probe = InMemoryProbe()
    add_stick(tmp_path, probe, "x", None)
    main(["--home", str(tmp_path / "h"), "devices"], probe=probe)
    assert "bindable : NO" in capsys.readouterr().out


def test_enroll_verify_list_revoke_cycle(run, stick):
    _, mount = stick
    code, out, _ = run("enroll", str(mount), "--label", "desk")
    assert code == 0 and "self-test passed" in out
    token_id = next(line.split(":")[1].strip() for line in out.splitlines() if "token id" in line)

    code, out, _ = run("verify")
    assert code == 0 and out.startswith("OK")

    code, out, _ = run("list")
    assert token_id in out and "active" in out and "desk" in out

    code, _, _ = run("revoke", token_id)
    assert code == 0
    code, _, err = run("verify")
    assert code == 1 and "token_revoked" in err
    assert "revoked" in run("list")[1]


def test_enroll_twice_requires_force(run, stick):
    _, mount = stick
    assert run("enroll", str(mount))[0] == 0
    code, _, err = run("enroll", str(mount))
    assert code == 1 and "already enrolled" in err
    code, out, _ = run("enroll", str(mount), "--force")
    assert code == 0 and "revoked" in out


def test_enroll_refuses_unusable_serial(run, probe, tmp_path):
    _, mount = add_stick(tmp_path, probe, "bad", "00000000")
    code, _, err = run("enroll", str(mount))
    assert code == 1 and "serial" in err


def test_verify_rejects_a_copied_token(run, probe, stick, tmp_path):
    _, mount = stick
    run("enroll", str(mount))
    _, clone = add_stick(tmp_path, probe, "clone", "EE00112233445566")
    shutil.copytree(mount / TOKEN_DIR, clone / TOKEN_DIR)
    code, _, err = run("verify", str(clone))
    assert code == 1 and "device_mismatch" in err


def test_passphrase_flow(run, stick, monkeypatch):
    _, mount = stick
    answers = iter(["s3cret", "s3cret", "s3cret"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("enroll", str(mount), "--passphrase")[0] == 0
    code, out, _ = run("verify")
    assert code == 0 and out.startswith("OK")


def test_passphrase_mismatch(run, stick, monkeypatch):
    _, mount = stick
    answers = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    code, _, err = run("enroll", str(mount), "--passphrase")
    assert code == 1 and "do not match" in err
    assert not (mount / TOKEN_DIR).exists()


def test_unsupported_platform_exit_code(monkeypatch, tmp_path, capsys):
    def boom():
        raise UnsupportedPlatformError("no probe for this OS")

    monkeypatch.setattr("usbtether.cli.default_probe", boom)
    assert main(["--home", str(tmp_path), "devices"]) == 3
    assert "no probe" in capsys.readouterr().err


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "usbtether" in capsys.readouterr().out
