"""The credential that lives on the USB drive.

Layout (``<mount>/.usbtether/``)::

    token.json       public, human-readable: format, version, token id, public key
    private_key.pem  Ed25519 private key (PKCS#8), optionally passphrase-encrypted

``token.json`` is written last, so a half-written enrollment is never mistaken for a valid
token. The private key never leaves the drive during enrollment; only the public key is
copied to the host-side registry.

Copying this directory to another drive copies the credential. What stops that copy from
authenticating is the device binding checked by the verifier, see ``docs/threat-model.md``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._util import atomic_write, utc_now_iso
from .errors import AlreadyEnrolledError, TokenError, TokenLockedError

TOKEN_DIR = ".usbtether"
TOKEN_FILE = "token.json"
KEY_FILE = "private_key.pem"
TOKEN_FORMAT = "usbtether-token"
TOKEN_VERSION = 1


@dataclass(frozen=True)
class Token:
    """Public description of a token found on a drive."""

    token_id: str
    public_key: bytes
    key_encrypted: bool
    created_at: str
    directory: Path

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")


def token_directory(mount: str | Path) -> Path:
    return Path(mount) / TOKEN_DIR


def has_token(mount: str | Path) -> bool:
    return (token_directory(mount) / TOKEN_FILE).is_file()


def create_token(
    mount: str | Path, passphrase: bytes | None = None, *, overwrite: bool = False
) -> Token:
    """Generate a new key pair and write the token to the drive at ``mount``."""
    root = Path(mount)
    if not root.is_dir():
        raise TokenError(f"{root} is not an accessible directory")
    directory = token_directory(root)
    token_file, key_file = directory / TOKEN_FILE, directory / KEY_FILE
    if token_file.exists() and not overwrite:
        raise AlreadyEnrolledError(f"{directory} already contains a token (use overwrite)")

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    token_id = str(uuid.uuid4())
    created_at = utc_now_iso()
    document = {
        "format": TOKEN_FORMAT,
        "version": TOKEN_VERSION,
        "token_id": token_id,
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "key_file": KEY_FILE,
        "key_encrypted": bool(passphrase),
        "created_at": created_at,
    }
    try:
        directory.mkdir(exist_ok=True)
        # Invalidate any previous token first, so a failure below cannot leave a stale one.
        token_file.unlink(missing_ok=True)
        atomic_write(key_file, pem, private=True)
        atomic_write(token_file, json.dumps(document, indent=2).encode("utf-8"))  # commit marker
    except OSError as exc:
        for leftover in (token_file, key_file):
            with contextlib.suppress(OSError):
                leftover.unlink(missing_ok=True)
        raise TokenError(f"could not write token to {directory}: {exc}") from exc
    return Token(token_id, public_raw, bool(passphrase), created_at, directory)


def read_token(mount: str | Path) -> Token:
    """Read and validate ``token.json`` from the drive at ``mount``."""
    directory = token_directory(mount)
    path = directory / TOKEN_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TokenError(f"no token found at {directory}") from exc
    except (OSError, ValueError) as exc:
        raise TokenError(f"cannot read {path}: {exc}") from exc
    try:
        if document["format"] != TOKEN_FORMAT or document["version"] != TOKEN_VERSION:
            raise TokenError(
                f"unsupported token format {document['format']!r} v{document['version']!r}"
            )
        token_id = str(uuid.UUID(document["token_id"]))
        public_key = base64.b64decode(document["public_key"], validate=True)
        if len(public_key) != 32:
            raise TokenError("public key must be 32 bytes")
        return Token(
            token_id=token_id,
            public_key=public_key,
            key_encrypted=bool(document["key_encrypted"]),
            created_at=str(document["created_at"]),
            directory=directory,
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise TokenError(f"{path} is malformed: {exc}") from exc


def load_private_key(token: Token, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    """Load the private key, checking that it matches the public key in ``token.json``."""
    try:
        pem = (token.directory / KEY_FILE).read_bytes()
    except OSError as exc:
        raise TokenError(f"cannot read private key: {exc}") from exc
    if token.key_encrypted and not passphrase:
        raise TokenLockedError("the private key is passphrase-protected")
    try:
        key = serialization.load_pem_private_key(
            pem, password=passphrase if token.key_encrypted else None
        )
    except (TypeError, ValueError) as exc:
        if token.key_encrypted:
            raise TokenLockedError("wrong passphrase or corrupt private key") from exc
        raise TokenError(f"corrupt private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TokenError("private key is not an Ed25519 key")
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != token.public_key:
        raise TokenError("private key does not match the public key in token.json")
    return key
