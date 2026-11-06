"""Open encrypted ``.utenc`` files transparently while the enrolled drive is plugged in.

The idea: the files you can see on disk are always encrypted. Double-clicking one runs
``usbtether open <file>`` (a per-user Windows file association, see
:func:`register_association`). That command checks the drive, decrypts the file into a private
working folder, opens it with whatever program normally handles the original name, and watches
it: every save is encrypted straight back over the ``.utenc``. When the drive is pulled out, or
the file has sat untouched for a while, the plain copy is deleted.

Honest limits: while a file is open its plain copy exists in the working folder
(``<home>/open``), readable by anything running as you. If the helper is killed, the next run
(or :func:`sweep`) syncs any unsaved change back and deletes the leftovers, but until then the
plain copy is on disk. Some editors (Notepad) keep no lock on the file, so "closed" cannot be
detected: the plain copy goes when the drive is removed or after ``idle_timeout`` seconds
without a save.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .errors import UsbTetherError
from .vault import SUFFIX, decrypt_file, encrypt_file

PROG_ID = "usbtether.encfile"
_CLASSES = r"Software\Classes"
_STATE = ".state"
_LOCK = ".lock"
_ALIVE_WITHIN = 5.0


# -- Windows file association -------------------------------------------------------------


def default_command(home: Path | None = None) -> str:
    """The command Windows runs for a double-clicked ``.utenc`` (no console window)."""
    exe = Path(sys.executable)
    windowless = exe.with_name("pythonw.exe")
    if windowless.exists():
        exe = windowless
    prefix = f'--home "{home}" ' if home else ""
    return f'"{exe}" -m usbtether {prefix}open "%1"'


def _winreg() -> Any:
    if sys.platform != "win32":
        raise UsbTetherError("registering a file association is implemented for Windows only")
    import winreg

    return winreg


def register_association(
    command: str | None = None, *, classes: str = _CLASSES, notify: bool = True
) -> str:
    """Make double-clicking ``*.utenc`` run ``usbtether open``. Per user (HKCU); no admin."""
    winreg = _winreg()
    command = command or default_command()
    hkcu = winreg.HKEY_CURRENT_USER
    with winreg.CreateKey(hkcu, rf"{classes}\{SUFFIX}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, PROG_ID)
    with winreg.CreateKey(hkcu, rf"{classes}\{PROG_ID}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "usbtether encrypted file")
    with winreg.CreateKey(hkcu, rf"{classes}\{PROG_ID}\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
    if notify:
        _notify_shell()
    return command


def association_command(*, classes: str = _CLASSES) -> str | None:
    """The registered command, or ``None`` if the association is not ours / not set."""
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{classes}\{SUFFIX}") as key:
            if winreg.QueryValueEx(key, "")[0] != PROG_ID:
                return None
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, rf"{classes}\{PROG_ID}\shell\open\command"
        ) as key:
            return str(winreg.QueryValueEx(key, "")[0])
    except OSError:
        return None


def unregister_association(*, classes: str = _CLASSES, notify: bool = True) -> bool:
    """Remove what :func:`register_association` wrote. Returns whether anything was removed."""
    winreg = _winreg()
    hkcu = winreg.HKEY_CURRENT_USER
    removed = False
    for sub in (
        rf"{classes}\{PROG_ID}\shell\open\command",
        rf"{classes}\{PROG_ID}\shell\open",
        rf"{classes}\{PROG_ID}\shell",
        rf"{classes}\{PROG_ID}",
    ):
        with contextlib.suppress(OSError):
            winreg.DeleteKey(hkcu, sub)
            removed = True
    if association_command(classes=classes) is None:
        # only drop the extension key if it still points at us
        with contextlib.suppress(OSError):
            with winreg.OpenKey(hkcu, rf"{classes}\{SUFFIX}") as key:
                ours = winreg.QueryValueEx(key, "")[0] == PROG_ID
            if ours:
                winreg.DeleteKey(hkcu, rf"{classes}\{SUFFIX}")
                removed = True
    if removed and notify:
        _notify_shell()
    return removed


def _notify_shell() -> None:
    import ctypes

    # SHCNE_ASSOCCHANGED: tell Explorer the associations changed.
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)


# -- Opening ------------------------------------------------------------------------------


def launch(path: Path) -> None:
    """Open ``path`` with the program the system associates with it."""
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])  # noqa: S603, S607
    else:
        subprocess.Popen(["xdg-open", str(path)])  # noqa: S603, S607


def _slot(home: Path, source: Path) -> Path:
    digest = hashlib.sha1(str(source.resolve()).lower().encode("utf-8")).hexdigest()[:16]  # noqa: S324
    return home / "open" / digest


def _read_state(slot: Path) -> dict[str, object]:
    try:
        data = json.loads((slot / _STATE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_state(slot: Path, source: Path, synced: str) -> None:
    (slot / _STATE).write_text(json.dumps({"src": str(source), "synced": synced}), encoding="utf-8")


def _sync_back(plain: Path, source: Path, key: bytes) -> str:
    """Encrypt ``plain`` over ``source``; returns the digest of what was synced."""
    digest = _digest(plain)
    encrypt_file(plain, key, dest_dir=source.parent, keep=True)
    return digest


def _signature(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size


def _locked(path: Path) -> bool:
    """True if another program holds the file open without sharing (Windows editors)."""
    try:
        os.rename(path, path)
    except PermissionError:
        return True
    except OSError:
        return False
    return False


def _wipe(slot: Path) -> None:
    shutil.rmtree(slot, ignore_errors=True)


def open_encrypted(
    source: Path,
    key: bytes,
    home: Path,
    *,
    present: Callable[[], bool],
    open_file: Callable[[Path], None] = launch,
    idle_timeout: float = 1800.0,
    poll: float = 1.0,
    on_event: Callable[[str], None] = lambda _: None,
) -> None:
    """Decrypt ``source`` to a working copy, open it, and keep it in sync until done.

    ``present`` says whether the drive is still plugged in. Returns when the drive is gone or
    the file has been idle for ``idle_timeout`` seconds; the working copy is removed by then.
    """
    if not source.name.endswith(SUFFIX) or not source.is_file():
        raise UsbTetherError(f"{source} is not a {SUFFIX} file")
    slot = _slot(home, source)
    plain = slot / source.name[: -len(SUFFIX)]
    lock = slot / _LOCK
    if lock.exists() and time.time() - lock.stat().st_mtime < _ALIVE_WITHIN and plain.exists():
        open_file(plain)  # another helper already owns this file: just bring it up again
        return
    _wipe(slot)
    slot.mkdir(parents=True)
    decrypt_file(source, key, dest_dir=slot, keep=True)
    synced = _digest(plain)
    _write_state(slot, source, synced)
    seen = _signature(plain)
    lock.write_text("1")
    open_file(plain)
    on_event(f"opened {plain.name}")
    last_change = time.monotonic()
    try:
        while present():
            lock.touch()
            sig = _signature(plain)
            # a save happened and has settled (no write for half a second)
            if sig is not None and sig != seen and time.time() - sig[0] / 1e9 > 0.5:
                try:
                    if _digest(plain) != synced:
                        synced = _sync_back(plain, source, key)
                        _write_state(slot, source, synced)
                        on_event(f"saved {plain.name}")
                    seen = sig
                    last_change = time.monotonic()
                except OSError:
                    pass  # still being written; try again next tick
            if time.monotonic() - last_change > idle_timeout and not _locked(plain):
                break
            time.sleep(poll)
    finally:
        with contextlib.suppress(OSError):
            if plain.exists() and _digest(plain) != synced:
                _sync_back(plain, source, key)
        _wipe(slot)
        on_event(f"closed {plain.name}")


def sweep(home: Path, key: bytes | None, *, stale_after: float = 10.0) -> int:
    """Clean up working copies whose helper died. Unsaved changes are synced back first.

    Without ``key`` a slot with unsynced changes is left alone. Returns how many were removed.
    """
    root = home / "open"
    removed = 0
    if not root.is_dir():
        return 0
    for slot in root.iterdir():
        lock = slot / _LOCK
        if not slot.is_dir():
            continue
        if lock.exists() and time.time() - lock.stat().st_mtime < stale_after:
            continue  # a live helper
        state = _read_state(slot)
        files = [p for p in slot.iterdir() if not p.name.startswith(".")]
        dirty = False
        for plain in files:
            if state.get("src") and _digest(plain) != state.get("synced"):
                if key is None:
                    dirty = True
                    continue
                with contextlib.suppress(OSError):
                    _sync_back(plain, Path(str(state["src"])), key)
        if not dirty:
            _wipe(slot)
            removed += 1
    return removed


# -- Bound folders ------------------------------------------------------------------------


class BoundFolders:
    """The folders the user asked to keep encrypted (a small JSON list in the state folder)."""

    def __init__(self, home: Path) -> None:
        self._file = home / "bound.json"

    def folders(self) -> list[Path]:
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            return [Path(p) for p in data.get("folders", [])]
        except (OSError, ValueError, AttributeError):
            return []

    def _save(self, folders: list[Path]) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps({"folders": [str(f) for f in folders]}), encoding="utf-8")

    def add(self, folder: Path) -> None:
        folder = folder.resolve()
        current = self.folders()
        if folder not in current:
            self._save([*current, folder])

    def remove(self, folder: Path) -> None:
        folder = folder.resolve()
        self._save([f for f in self.folders() if f.resolve() != folder])


def protect_folder(folder: Path, key: bytes, *, quiet_seconds: float = 2.0) -> int:
    """Encrypt every plain file in ``folder`` that nothing has touched for ``quiet_seconds``.

    Files that are still being written or are locked by a program are left for the next pass.
    Returns the number of files encrypted.
    """
    done = 0
    now = time.time()
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name.endswith((SUFFIX, ".tmp")):
            continue
        try:
            if now - path.stat().st_mtime < quiet_seconds or _locked(path):
                continue
            encrypt_file(path, key)
            done += 1
        except OSError:
            continue
    return done
