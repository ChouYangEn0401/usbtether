"""Host-side registry: the trust anchor of the system.

The registry records, for every enrolled token, its **public key** and the **fingerprint of
the physical drive** it was enrolled on. Because this data lives on the host and not on the
drive, copying the drive's files does not copy it.

The registry file is *not* itself signed or encrypted. Anyone who can write to it can enrol
arbitrary tokens, so it must be protected like any other credential store of the host.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ._util import atomic_write, utc_now_iso
from .errors import RegistryError

REGISTRY_VERSION = 1

ACTIVE = "active"
REVOKED = "revoked"


def default_home() -> Path:
    """Directory for host-side state. Override with the ``USBTETHER_HOME`` variable."""
    explicit = os.environ.get("USBTETHER_HOME")
    if explicit:
        return Path(explicit)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "usbtether"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "usbtether"


@dataclass
class RegistryEntry:
    token_id: str
    public_key: str  # base64 of the raw 32-byte Ed25519 public key
    fingerprint: str  # device fingerprint, see usbtether.device
    device: dict[str, Any]  # DeviceReport.to_dict() at enrollment time
    enrolled_at: str
    label: str | None = None
    status: str = ACTIVE
    revoked_at: str | None = None

    @property
    def is_active(self) -> bool:
        return self.status == ACTIVE


class Registry:
    """JSON-file registry. Safe for concurrent use within one process."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    @classmethod
    def default(cls) -> Registry:
        return cls(default_home() / "registry.json")

    # -- persistence ------------------------------------------------------------------

    def _load(self) -> dict[str, RegistryEntry]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RegistryError(f"cannot read registry {self.path}: {exc}") from exc
        try:
            if raw["version"] != REGISTRY_VERSION:
                raise RegistryError(f"unsupported registry version {raw['version']!r}")
            return {tid: RegistryEntry(**fields) for tid, fields in raw["entries"].items()}
        except (KeyError, TypeError) as exc:
            raise RegistryError(f"registry {self.path} is malformed: {exc}") from exc

    def _save(self, entries: dict[str, RegistryEntry]) -> None:
        document = {
            "version": REGISTRY_VERSION,
            "entries": {tid: asdict(entry) for tid, entry in entries.items()},
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(
                self.path,
                json.dumps(document, indent=2, sort_keys=True).encode("utf-8"),
                private=True,
            )
        except OSError as exc:
            raise RegistryError(f"cannot write registry {self.path}: {exc}") from exc

    # -- queries ----------------------------------------------------------------------

    def get(self, token_id: str) -> RegistryEntry | None:
        with self._lock:
            return self._load().get(token_id)

    def entries(self) -> list[RegistryEntry]:
        with self._lock:
            return sorted(self._load().values(), key=lambda e: e.enrolled_at)

    def active_for_fingerprint(self, fingerprint: str) -> list[RegistryEntry]:
        return [e for e in self.entries() if e.is_active and e.fingerprint == fingerprint]

    # -- mutations --------------------------------------------------------------------

    def add(self, entry: RegistryEntry) -> None:
        with self._lock:
            entries = self._load()
            if entry.token_id in entries:
                raise RegistryError(f"token {entry.token_id} is already registered")
            entries[entry.token_id] = entry
            self._save(entries)

    def remove(self, token_id: str) -> None:
        """Delete an entry outright. Used only to roll back a failed enrollment."""
        with self._lock:
            entries = self._load()
            if entries.pop(token_id, None) is not None:
                self._save(entries)

    def revoke(self, token_id: str) -> RegistryEntry:
        with self._lock:
            entries = self._load()
            entry = entries.get(token_id)
            if entry is None:
                raise RegistryError(f"unknown token {token_id}")
            if entry.is_active:
                entry.status = REVOKED
                entry.revoked_at = utc_now_iso()
                self._save(entries)
            return entry
