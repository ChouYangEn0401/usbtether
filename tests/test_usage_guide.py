"""Every message the usage guide promises must be what the CLI really prints.

Each case triggers the situation, asserts the fragment in the real output, and asserts the
same fragment is documented in both language versions of docs/usage*.md. If the code or the
guide changes on its own, this test fails.
"""

import shutil
from pathlib import Path

import pytest

from usbtether.cli import main
from usbtether.probe.memory import InMemoryProbe
from usbtether.token import TOKEN_DIR

from .conftest import add_stick

DOCS = Path(__file__).resolve().parents[1] / "docs"
GUIDES = [(DOCS / "usage.md").read_text("utf-8"), (DOCS / "usage.zh-TW.md").read_text("utf-8")]


class Cli:
    def __init__(self, probe, home, capsys):
        self.probe, self.home, self.capsys = probe, home, capsys

    def __call__(self, *argv, home=None):
        code = main(["--home", str(home or self.home), *argv], probe=self.probe)
        out = self.capsys.readouterr()
        return code, out.out + out.err


@pytest.fixture
def cli(probe, tmp_path, capsys):
    return Cli(probe, tmp_path / "home", capsys)


def documented(fragment):
    for guide in GUIDES:
        assert fragment in guide, f"{fragment!r} is not documented"


def test_no_devices(tmp_path, capsys):
    code = main(["--home", str(tmp_path), "devices"], probe=InMemoryProbe())
    out = capsys.readouterr().out
    assert code == 0
    for fragment in ("No USB mass-storage devices found.",):
        assert fragment in out
        documented(fragment)


def test_not_mounted(cli):
    code, out = cli("verify", "/nonexistent")
    assert code == 1 and "no USB drive is mounted at" in out
    documented("no USB drive is mounted at")


def test_no_enrolled_drive_plugged_in(cli, stick):
    code, out = cli("verify")
    assert code == 1 and "no USB drive with a usbtether token is plugged in" in out
    documented("no USB drive with a usbtether token is plugged in")


def test_several_enrolled_drives(cli, stick, probe, tmp_path):
    _, mount = stick
    _, second = add_stick(tmp_path, probe, "second", "CC11223344556677")
    cli("enroll", str(mount))
    cli("enroll", str(second))
    code, out = cli("verify")
    assert code == 1 and "several enrolled drives are plugged in" in out
    documented("several enrolled drives are plugged in")


def test_unbindable_drive(cli, probe, tmp_path):
    _, mount = add_stick(tmp_path, probe, "nameless", None)
    assert "bindable : NO" in cli("devices")[1]
    code, out = cli("enroll", str(mount))
    assert code == 1 and "cannot be bound" in out
    for fragment in ("bindable : NO", "cannot be bound"):
        documented(fragment)


def test_already_enrolled_needs_force(cli, stick):
    _, mount = stick
    cli("enroll", str(mount))
    code, out = cli("enroll", str(mount))
    assert code == 1 and "already enrolled" in out and "--force" in out
    documented("already enrolled")
    assert cli("enroll", str(mount), "--force")[0] == 0


def test_failure_reasons(cli, stick, probe, tmp_path):
    _, mount = stick
    cli("enroll", str(mount))

    # device_mismatch: the token copied to another physical drive
    _, clone = add_stick(tmp_path, probe, "clone", "EE00112233445566")
    shutil.copytree(mount / TOKEN_DIR, clone / TOKEN_DIR)
    code, out = cli("verify", str(clone))
    assert code == 1 and "FAILED  device_mismatch" in out

    # unknown_token: a computer whose registry has no entry for this token
    code, out = cli("verify", str(mount), home=tmp_path / "other-pc")
    assert code == 1 and "FAILED  unknown_token" in out

    # token_revoked
    token_id = next(line.split()[0] for line in cli("list")[1].splitlines() if "active" in line)
    cli("revoke", token_id)
    code, out = cli("verify", str(mount))
    assert code == 1 and "FAILED  token_revoked" in out

    for fragment in ("FAILED  device_mismatch", "FAILED  unknown_token", "FAILED  token_revoked"):
        documented(fragment)


def test_wrong_passphrase_message(cli, stick, monkeypatch):
    _, mount = stick
    answers = iter(["right", "right", "wrong"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli("enroll", str(mount), "--passphrase")[0] == 0
    code, out = cli("verify")
    assert code == 1 and "wrong passphrase or corrupt private key" in out
    documented("wrong passphrase or corrupt private key")


def test_force_reenroll_does_not_need_the_forgotten_passphrase(cli, stick, monkeypatch):
    """The usage guide promises: forgot the passphrase -> `enroll --force` replaces the key."""
    _, mount = stick
    answers = iter(["forgotten", "forgotten"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli("enroll", str(mount), "--passphrase")[0] == 0
    code, out = cli("enroll", str(mount), "--force")  # no passphrase prompt is consumed
    assert code == 0 and "self-test passed" in out
    assert cli("verify")[0] == 0


def test_wiped_drive_can_be_reenrolled_with_force(cli, stick):
    _, mount = stick
    cli("enroll", str(mount))
    shutil.rmtree(mount / TOKEN_DIR)
    assert cli("enroll", str(mount))[0] == 1  # the computer still remembers the drive
    assert cli("enroll", str(mount), "--force")[0] == 0
    assert cli("verify")[0] == 0


def test_exit_codes_table_matches_the_cli(cli, stick, tmp_path, monkeypatch):
    from usbtether.errors import UnsupportedPlatformError

    _, mount = stick
    assert cli("devices")[0] == 0  # 0 success
    assert cli("verify", "/nonexistent")[0] == 1  # 1 failure
    with pytest.raises(SystemExit) as exc:  # 2 usage
        main(["--home", str(tmp_path), "bogus-command"])
    assert exc.value.code == 2

    def boom():
        raise UnsupportedPlatformError("no probe")

    monkeypatch.setattr("usbtether.cli.default_probe", boom)
    assert main(["--home", str(tmp_path), "devices"]) == 3  # 3 platform
    del mount
