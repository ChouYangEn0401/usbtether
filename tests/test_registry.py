import json

import pytest

from usbtether.errors import RegistryError
from usbtether.registry import ACTIVE, REVOKED, Registry, RegistryEntry, default_home


def entry(token_id="t1", fingerprint="f1") -> RegistryEntry:
    return RegistryEntry(
        token_id=token_id,
        public_key="AAAA",
        fingerprint=fingerprint,
        device={"vendor_id": "0781"},
        enrolled_at="2026-01-01T00:00:00Z",
        label="work",
    )


def test_empty_registry(tmp_path):
    registry = Registry(tmp_path / "r.json")
    assert registry.entries() == []
    assert registry.get("nope") is None


def test_add_get_persist(tmp_path):
    path = tmp_path / "sub" / "r.json"
    Registry(path).add(entry())
    reloaded = Registry(path).get("t1")
    assert reloaded is not None
    assert reloaded.label == "work"
    assert reloaded.status == ACTIVE


def test_duplicate_token_rejected(tmp_path):
    registry = Registry(tmp_path / "r.json")
    registry.add(entry())
    with pytest.raises(RegistryError, match="already registered"):
        registry.add(entry())


def test_revoke_is_idempotent_and_recorded(tmp_path):
    registry = Registry(tmp_path / "r.json")
    registry.add(entry())
    first = registry.revoke("t1")
    assert first.status == REVOKED
    stamp = first.revoked_at
    assert registry.revoke("t1").revoked_at == stamp
    assert registry.active_for_fingerprint("f1") == []


def test_revoke_unknown(tmp_path):
    with pytest.raises(RegistryError):
        Registry(tmp_path / "r.json").revoke("ghost")


def test_active_for_fingerprint(tmp_path):
    registry = Registry(tmp_path / "r.json")
    registry.add(entry("a", "f1"))
    registry.add(entry("b", "f2"))
    assert [e.token_id for e in registry.active_for_fingerprint("f2")] == ["b"]


def test_remove_for_rollback(tmp_path):
    registry = Registry(tmp_path / "r.json")
    registry.add(entry())
    registry.remove("t1")
    registry.remove("t1")  # no error
    assert registry.entries() == []


def test_corrupt_files_are_reported(tmp_path):
    path = tmp_path / "r.json"
    path.write_text("{ nope")
    with pytest.raises(RegistryError):
        Registry(path).entries()
    path.write_text(json.dumps({"version": 7, "entries": {}}))
    with pytest.raises(RegistryError):
        Registry(path).entries()
    path.write_text(json.dumps({"version": 1, "entries": {"x": {"bogus": 1}}}))
    with pytest.raises(RegistryError):
        Registry(path).entries()


def test_default_home_respects_override(monkeypatch, tmp_path):
    monkeypatch.setenv("USBTETHER_HOME", str(tmp_path))
    assert default_home() == tmp_path
