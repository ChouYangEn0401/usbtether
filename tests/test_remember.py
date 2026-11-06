"""`--remember`: unlock with a secret kept on this computer instead of typing a passphrase."""

import pytest

from usbtether import Agent, FileSecretStore, NullSecretStore, Verifier, enroll
from usbtether.cli import main
from usbtether.errors import TokenLockedError, UsbTetherError
from usbtether.protocol import AuthResult, FailureReason
from usbtether.token import KEY_FILE, TOKEN_DIR, read_token


@pytest.fixture
def store(tmp_path):
    return FileSecretStore(tmp_path / "host-secrets")


def must_not_be_called():
    raise AssertionError("a passphrase was requested although the host secret should unlock it")


def test_remembered_key_unlocks_without_any_passphrase(stick, probe, registry, store):
    _, mount = stick
    result = enroll(probe, registry, mount, remember=True, secret_store=store)
    assert result.protection == "host-secret"
    token = read_token(mount)
    assert token.key_encrypted
    assert b"ENCRYPTED" in (mount / TOKEN_DIR / KEY_FILE).read_bytes()
    assert store.get(token.token_id) is not None

    agent = Agent(probe, passphrase=must_not_be_called, secret_store=store)
    assert Verifier(registry).authenticate(agent, "login", mount).ok


def test_the_drive_alone_is_useless(stick, probe, registry, store):
    """A lost or stolen drive, without this computer's secret store, cannot be unlocked."""
    _, mount = stick
    enroll(probe, registry, mount, remember=True, secret_store=store)
    verifier = Verifier(registry)
    with pytest.raises(TokenLockedError):
        verifier.authenticate(Agent(probe, secret_store=NullSecretStore()), "login", mount)
    # Another computer's store holds no secret for this token either.
    elsewhere = FileSecretStore(store.directory.parent / "other-computer")
    with pytest.raises(TokenLockedError):
        verifier.authenticate(Agent(probe, secret_store=elsewhere), "login", mount)
    # And guessing a secret does not work.
    elsewhere.put(read_token(mount).token_id, b"a-wrong-secret")
    with pytest.raises(TokenLockedError):
        verifier.authenticate(Agent(probe, secret_store=elsewhere), "login", mount)


def test_default_store_is_used_when_none_is_given(stick, probe, registry):
    """enroll() and Agent() agree on the default store, so library users need no setup."""
    _, mount = stick
    enroll(probe, registry, mount, remember=True)
    assert Verifier(registry).authenticate(Agent(probe), "login", mount).ok


def test_remember_and_passphrase_are_mutually_exclusive(stick, probe, registry, store):
    _, mount = stick
    with pytest.raises(UsbTetherError, match="either"):
        enroll(probe, registry, mount, remember=True, passphrase=b"x", secret_store=store)
    assert not (mount / TOKEN_DIR).exists()


def test_failed_enrollment_leaves_no_secret_behind(stick, probe, registry, store, monkeypatch):
    _, mount = stick
    monkeypatch.setattr(
        "usbtether.enrollment.Verifier.authenticate",
        lambda *a, **k: AuthResult(False, reason=FailureReason.BAD_SIGNATURE),
    )
    with pytest.raises(UsbTetherError, match="self-test"):
        enroll(probe, registry, mount, remember=True, secret_store=store)
    assert list(store.directory.glob("*.bin")) == []
    assert registry.entries() == []
    assert not (mount / TOKEN_DIR).exists()


def test_reenrolling_discards_the_stale_secret(stick, probe, registry, store):
    _, mount = stick
    first = enroll(probe, registry, mount, remember=True, secret_store=store)
    second = enroll(probe, registry, mount, overwrite=True, secret_store=store)
    assert store.get(first.token.token_id) is None
    assert second.protection == "none"
    assert Verifier(registry).authenticate(Agent(probe, secret_store=store), "login", mount).ok


def test_typed_passphrase_still_works_when_the_store_is_empty(stick, probe, registry, store):
    _, mount = stick
    enroll(probe, registry, mount, passphrase=b"typed", secret_store=store)
    agent = Agent(probe, passphrase=b"typed", secret_store=store)
    assert Verifier(registry).authenticate(agent, "login", mount).ok


# -- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def run(probe, tmp_path, capsys, monkeypatch):
    home = tmp_path / "cli-home"
    monkeypatch.setattr("getpass.getpass", lambda prompt="": pytest.fail("asked for a passphrase"))

    def _run(*argv):
        code = main(["--home", str(home), *argv], probe=probe)
        out = capsys.readouterr()
        return code, out.out + out.err

    _run.home = home
    return _run


def test_cli_remember_then_verify_never_prompts(run, stick):
    _, mount = stick
    code, out = run("enroll", str(mount), "--remember")
    assert code == 0 and "secret stored on this computer" in out and "this computer only" in out
    code, out = run("verify")
    assert code == 0 and out.startswith("OK")  # getpass would have failed the test


def test_cli_revoke_forgets_the_secret(run, stick):
    _, mount = stick
    run("enroll", str(mount), "--remember")
    secret_files = list((run.home / "secrets").glob("*.bin"))
    assert len(secret_files) == 1
    token_id = secret_files[0].stem
    assert run("revoke", token_id)[0] == 0
    assert list((run.home / "secrets").glob("*.bin")) == []


def test_cli_remember_conflicts_with_passphrase(run, stick, capsys):
    _, mount = stick
    with pytest.raises(SystemExit) as exc:
        main(["--home", str(run.home), "enroll", str(mount), "--remember", "--passphrase"])
    assert exc.value.code == 2
