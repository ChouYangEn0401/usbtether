import json

import pytest

from usbtether.errors import AlreadyEnrolledError, TokenError, TokenLockedError
from usbtether.token import (
    KEY_FILE,
    TOKEN_DIR,
    TOKEN_FILE,
    create_token,
    has_token,
    load_private_key,
    read_token,
)


def test_create_and_read_roundtrip(tmp_path):
    created = create_token(tmp_path)
    assert has_token(tmp_path)
    loaded = read_token(tmp_path)
    assert loaded.token_id == created.token_id
    assert loaded.public_key == created.public_key
    assert len(loaded.public_key) == 32
    assert not loaded.key_encrypted
    key = load_private_key(loaded)
    assert key.public_key() is not None


def test_refuses_to_overwrite_unless_asked(tmp_path):
    first = create_token(tmp_path)
    with pytest.raises(AlreadyEnrolledError):
        create_token(tmp_path)
    second = create_token(tmp_path, overwrite=True)
    assert second.token_id != first.token_id
    assert read_token(tmp_path).token_id == second.token_id


def test_passphrase_protection(tmp_path):
    create_token(tmp_path, passphrase=b"correct horse")
    token = read_token(tmp_path)
    assert token.key_encrypted
    assert b"ENCRYPTED" in (tmp_path / TOKEN_DIR / KEY_FILE).read_bytes()
    with pytest.raises(TokenLockedError):
        load_private_key(token)
    with pytest.raises(TokenLockedError):
        load_private_key(token, b"wrong")
    assert load_private_key(token, b"correct horse") is not None


def test_unencrypted_key_ignores_passphrase_argument(tmp_path):
    create_token(tmp_path)
    assert load_private_key(read_token(tmp_path), b"unused") is not None


def test_missing_token_is_a_clean_error(tmp_path):
    assert not has_token(tmp_path)
    with pytest.raises(TokenError, match="no token"):
        read_token(tmp_path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(format="something-else"),
        lambda d: d.update(version=99),
        lambda d: d.update(token_id="not-a-uuid"),
        lambda d: d.update(public_key="!!!"),
        lambda d: d.update(public_key="AAAA"),
        lambda d: d.pop("key_encrypted"),
    ],
)
def test_malformed_token_json_is_rejected(tmp_path, mutate):
    create_token(tmp_path)
    path = tmp_path / TOKEN_DIR / TOKEN_FILE
    document = json.loads(path.read_text())
    mutate(document)
    path.write_text(json.dumps(document))
    with pytest.raises(TokenError):
        read_token(tmp_path)


def test_swapped_public_key_is_detected(tmp_path):
    """token.json and the private key must belong together."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    create_token(a)
    create_token(b)
    other = read_token(b)
    path = a / TOKEN_DIR / TOKEN_FILE
    document = json.loads(path.read_text())
    document["public_key"] = other.public_key_b64
    path.write_text(json.dumps(document))
    with pytest.raises(TokenError, match="does not match"):
        load_private_key(read_token(a))


def test_failed_write_leaves_no_valid_token(tmp_path, monkeypatch):
    import usbtether.token as module

    def boom(path, data, **kwargs):
        if path.name == TOKEN_FILE:
            raise OSError("disk unplugged")
        return real(path, data, **kwargs)

    real = module.atomic_write
    monkeypatch.setattr(module, "atomic_write", boom)
    with pytest.raises(TokenError, match="could not write"):
        create_token(tmp_path)
    assert not has_token(tmp_path)
    assert not (tmp_path / TOKEN_DIR / KEY_FILE).exists()


def test_not_a_directory(tmp_path):
    with pytest.raises(TokenError):
        create_token(tmp_path / "missing")
