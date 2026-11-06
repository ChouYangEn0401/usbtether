"""usbtether web demo.

A small FastAPI app that exercises the library end to end:

* **USB Authentication**: enroll the drive and verify it from the page (what the CLI's
  ``enroll`` and ``verify`` do), so the other two experiments have something to work with.
* **Software Guard**: a 12-step workflow. Every step needs a fresh challenge-response with
  the enrolled USB drive and yields a single-use, scoped, 8-second capability. Unplugging the
  drive revokes the session.
* **Vault Unlock Lab**: unlock a fictional vault either by solving a puzzle or with a
  USB-backed challenge-response bound to that one vault challenge.
* **Encrypt / Decrypt**: one-off encryption of files or folders anywhere on this computer with
  the drive's key; in place or to another folder, keeping or deleting the source.
* **Bound folders**: folders that stay encrypted on disk. With the ``.utenc`` file association
  registered, double-clicking a file decrypts it to a working copy, opens it, and encrypts every
  save back (``usbtether open``, see ``usbtether.opener``).

This is an experiment harness, **not** a deployable service. It has no user authentication,
runs the agent and the verifier in one process, and refuses to bind to non-loopback
addresses.

Run (after ``usbtether enroll E:``)::

    pip install -e ".[demo]"
    python examples/web_demo/app.py

If the drive's key is passphrase-protected, export ``USBTETHER_PASSPHRASE`` first.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from usbtether.agent import Agent
from usbtether.authz import Authorizer, Capability
from usbtether.enrollment import enroll
from usbtether.errors import (
    AlreadyEnrolledError,
    AuthorizationError,
    TokenLockedError,
    UnsupportedDeviceError,
    UsbTetherError,
)
from usbtether.monitor import PresenceMonitor
from usbtether.opener import (
    BoundFolders,
    association_command,
    default_command,
    protect_folder,
    register_association,
    sweep,
    unregister_association,
)
from usbtether.probe import DeviceProbe, default_probe
from usbtether.registry import Registry, default_home
from usbtether.secretstore import HostSecretStore
from usbtether.vault import SUFFIX, decrypt_file, drive_key, encrypt_file
from usbtether.verifier import Verifier

RESOURCE = "demo-workflow"
RETRY_MS = 2500
DEFAULT_CLASSES = r"Software\Classes"
# Failures that retrying will not fix: the session is gone or the drive is the wrong one.
FATAL_REASONS = {
    "session_inactive",
    "unknown_session",
    "device_mismatch",
    "token_revoked",
    "unknown_token",
    "bad_signature",
    "token_mismatch",
    "device_unsupported",
}


class EnrollRequest(BaseModel):
    mount: str
    remember: bool = True
    force: bool = False


class VerifyRequest(BaseModel):
    mount: str | None = None


class BoxAuto(BaseModel):
    auto: bool


class CryptPick(BaseModel):
    kind: str = "files"  # "files" | "folder" | "encrypted"


class CryptRequest(BaseModel):
    paths: list[str]
    delete_source: bool = False
    dest: str = "inplace"  # "inplace" | "custom"
    dest_dir: str | None = None


_PICK_SCRIPT = """
import json, tkinter as tk
from tkinter import filedialog
r = tk.Tk(); r.withdraw(); r.attributes("-topmost", True)
k = "__KIND__"
if k == "folder":
    p = filedialog.askdirectory(); out = [p] if p else []
elif k == "encrypted":
    out = list(filedialog.askopenfilenames(filetypes=[("usbtether files", "*.utenc")]))
else:
    out = list(filedialog.askopenfilenames())
print(json.dumps(out))
"""


class DropItem(BaseModel):
    name: str
    size: int | None = None
    mtime: float | None = None  # milliseconds, as File.lastModified gives it
    dir: bool = False


class DropResolve(BaseModel):
    items: list[DropItem]


class BindPath(BaseModel):
    path: str


_SKIP_DIRS = {"AppData", "node_modules", "__pycache__", "$Recycle.Bin", "site-packages"}


def _default_roots() -> list[Path]:
    home = Path.home()
    names = ["Desktop", "Downloads", "Documents", "Pictures", "Videos", "Music"]
    roots = [home / n for n in names]
    roots += [p / n for p in home.glob("OneDrive*") for n in names]
    return [r for r in roots if r.is_dir()] + [home]


def _resolve_drops(
    items: list[DropItem], roots: list[Path], *, max_depth: int = 5, budget: int = 200_000
) -> tuple[list[str], list[str]]:
    """Match dragged-in names (plus size and mtime for files) against a shallow disk walk.

    A browser never tells the page where a dropped file lives, but the demo runs on the same
    computer, so it can look for it. A file must match name, size and modification time; a
    folder only its name, so a folder name found in two places counts as not found.
    """
    wanted = {i.name for i in items}
    hits: dict[str, list[Path]] = {n: [] for n in wanted}
    seen: set[Path] = set()
    for root in roots:
        top = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            if here in seen:
                dirnames[:] = []
                continue
            seen.add(here)
            budget -= len(dirnames) + len(filenames)
            depth = len(here.parts) - top
            dirnames[:] = [
                d
                for d in dirnames
                if depth < max_depth
                and not d.startswith(".")
                and d not in _SKIP_DIRS
                and (root != Path.home() or depth == 0)
            ]
            for n in [*dirnames, *filenames]:
                if n in hits and here / n not in hits[n]:
                    hits[n].append(here / n)
            if budget <= 0:
                break
    found, missing = [], []
    for item in items:
        matches = [p for p in hits[item.name] if p.is_dir() == item.dir]
        if not item.dir:
            matches = [
                p
                for p in matches
                if (item.size is None or p.stat().st_size == item.size)
                and (item.mtime is None or abs(p.stat().st_mtime * 1000 - item.mtime) < 2000)
            ]
        if len(matches) == 1 or (matches and not item.dir):
            found.append(str(matches[0]))
        else:
            missing.append(item.name)
    return found, missing


def _spawn_detached(args: list[str]) -> None:
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(  # noqa: S603
        args,
        creationflags=flags,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class GuardStart(BaseModel):
    total_steps: int = 12


class GuardAuthorize(BaseModel):
    session_id: str
    step: int


class GuardConsume(BaseModel):
    session_id: str
    step: int
    capability: dict[str, Any]


class VaultSolve(BaseModel):
    challenge_id: str
    answer: int


class VaultUsb(BaseModel):
    challenge_id: str


def _explain(exc: Exception) -> tuple[str, bool]:
    """Human message and whether retrying is pointless."""
    if isinstance(exc, AuthorizationError):
        return f"{exc.reason}: {exc}", exc.reason in FATAL_REASONS
    if isinstance(exc, TokenLockedError):
        return (
            "The key is passphrase-protected. Enroll it again with "
            "'usbtether enroll <drive> --remember --force' (unlocks automatically on this "
            "computer), or set USBTETHER_PASSPHRASE and restart.",
            True,
        )
    if isinstance(exc, UnsupportedDeviceError):
        return str(exc), True
    return str(exc), False


def create_app(
    probe: DeviceProbe | None = None,
    registry: Registry | None = None,
    *,
    passphrase: bytes | None = None,
    secret_store: HostSecretStore | None = None,
    monitor_interval: float | None = 1.0,
    state_home: Path | None = None,
    search_roots: list[Path] | None = None,
    assoc_classes: str = DEFAULT_CLASSES,
    launcher: Callable[[list[str]], Any] | None = None,
) -> FastAPI:
    """Build the app. ``monitor_interval=None`` disables the background thread (for tests).

    ``state_home`` overrides where bound folders and working copies are kept,
    ``search_roots`` where dragged-in items are looked up, ``assoc_classes`` the registry key
    the file association is written under, and ``launcher`` how ``usbtether open`` is spawned.
    """
    launcher = launcher or _spawn_detached
    probe = probe or default_probe()
    registry = registry or Registry.default()
    if passphrase is None and os.environ.get("USBTETHER_PASSPHRASE"):
        passphrase = os.environ["USBTETHER_PASSPHRASE"].encode("utf-8")

    verifier = Verifier(registry)
    authorizer = Authorizer(verifier)
    agent = Agent(probe, passphrase=passphrase, secret_store=secret_store)
    monitor = PresenceMonitor(probe, authorizer, interval=monitor_interval or 1.0)
    workflows: dict[str, dict[str, int]] = {}
    vault: dict[str, dict[str, Any]] = {}
    html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if monitor_interval is not None:
            monitor.start()
            app.state.bind_start()
        try:
            yield
        finally:
            monitor.stop()
            if monitor_interval is not None:
                app.state.bind_stop.set()

    app = FastAPI(title="usbtether demo", lifespan=lifespan)
    app.state.authorizer = authorizer
    app.state.verifier = verifier
    app.state.monitor = monitor

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return html

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        try:
            devices = probe.list_devices()
            probe_error = None
        except UsbTetherError as exc:
            devices, probe_error = [], str(exc)
        listed = []
        for d in devices:
            enrolled = d.is_bindable and bool(registry.active_for_fingerprint(d.fingerprint))
            listed.append(
                {
                    "id": f"{d.vendor_id}:{d.product_id}",
                    "product": d.product,
                    "serial_quality": d.serial_quality.value,
                    "bindable": d.is_bindable,
                    "enrolled": enrolled,
                    "mounts": [v.mount_point for v in d.volumes],
                }
            )
        return {
            "devices": listed,
            "ready": any(x["enrolled"] for x in listed),
            "probe_error": probe_error,
            "sessions": [
                {
                    "id": s.session_id[:8],
                    "active": s.is_active(time.time()),
                    "reason": s.revoked_reason,
                }
                for s in list(authorizer._sessions.values())[-5:]
            ],
        }

    # -- USB Authentication --------------------------------------------------------------

    @app.post("/api/usb/enroll")
    def usb_enroll(req: EnrollRequest) -> dict[str, Any]:
        try:
            result = enroll(
                probe,
                registry,
                req.mount,
                remember=req.remember,
                secret_store=secret_store,
                overwrite=req.force,
            )
        except UsbTetherError as exc:
            return {
                "ok": False,
                "message": str(exc),
                "already": isinstance(exc, AlreadyEnrolledError),
            }
        return {
            "ok": True,
            "token_id": result.token.token_id,
            "device": f"{result.device.vendor_id}:{result.device.product_id}",
            "protection": result.protection,
            "revoked": list(result.revoked),
            "message": "Enrolled. A challenge-response self-test passed.",
        }

    @app.post("/api/usb/verify")
    def usb_verify(req: VerifyRequest) -> dict[str, Any]:
        try:
            result = verifier.authenticate(agent, "web-verify", req.mount)
        except UsbTetherError as exc:
            return {"ok": False, "message": _explain(exc)[0]}
        if not result.ok:
            reason = result.reason.value if result.reason else "failed"
            return {"ok": False, "message": f"{reason}: {result.detail or 'verification failed'}"}
        return {
            "ok": True,
            "token_id": result.token_id,
            "warnings": list(result.warnings),
            "message": "Challenge-response accepted. This is the drive that was enrolled.",
        }

    # -- 03 Encrypt / Decrypt: one-off, for files anywhere on this computer --------------

    home_dir = state_home or default_home()
    default_dest = home_dir / "encrypted"

    @app.post("/api/crypt/pick")
    def crypt_pick(req: CryptPick) -> dict[str, Any]:
        """Open a native file/folder dialog on this machine (the page cannot see real paths)."""
        if req.kind not in {"files", "folder", "encrypted"}:
            raise HTTPException(400, "kind must be files, folder or encrypted")
        script = _PICK_SCRIPT.replace("__KIND__", req.kind)
        try:
            out = subprocess.run(  # noqa: S603 - fixed script, kind is whitelisted
                [sys.executable, "-I", "-c", script], capture_output=True, text=True, timeout=300
            )
            paths = json.loads(out.stdout.strip() or "[]")
        except (subprocess.SubprocessError, ValueError, OSError) as exc:
            return {"ok": False, "paths": [], "message": f"No file dialog available: {exc}"}
        return {"ok": True, "paths": [str(p) for p in paths]}

    @app.post("/api/crypt/resolve")
    def crypt_resolve(req: DropResolve) -> dict[str, Any]:
        """Find the real paths of dragged-in items (browsers only reveal the name)."""
        found, missing = _resolve_drops(req.items, search_roots or _default_roots())
        return {"paths": found, "missing": missing}

    @app.get("/api/crypt/info")
    def crypt_info() -> dict[str, Any]:
        return {"default_dest": str(default_dest)}

    def _crypt(req: CryptRequest, *, encrypt: bool) -> dict[str, Any]:
        if req.dest == "custom" and not (req.dest_dir or "").strip():
            return {"ok": False, "message": "Choose a destination folder."}
        out_root = Path((req.dest_dir or "").strip()).expanduser() if req.dest == "custom" else None
        todo: list[tuple[Path, Path | None]] = []
        for raw in req.paths:
            p = Path(raw).expanduser()
            if p.is_dir():
                for f in sorted(x for x in p.rglob("*") if x.is_file()):
                    sub = f.parent.relative_to(p.parent)
                    todo.append((f, out_root / sub if out_root else None))
            elif p.is_file():
                todo.append((p, out_root))
            else:
                return {"ok": False, "message": f"Not found: {raw}"}
        todo = [
            (f, d)
            for f, d in todo
            if not f.name.endswith(".tmp") and f.name.endswith(SUFFIX) != encrypt
        ]
        if not todo:
            what = "nothing to encrypt (already .utenc?)" if encrypt else "no .utenc files selected"
            return {"ok": False, "message": f"Skipped: {what}."}
        try:
            key = drive_key(agent, verifier)
            done = []
            for f, d in todo:
                fn = encrypt_file if encrypt else decrypt_file
                done.append(str(fn(f, key, dest_dir=d, keep=not req.delete_source)))
        except UsbTetherError as exc:
            return {"ok": False, "message": _explain(exc)[0]}
        except OSError as exc:
            return {"ok": False, "message": f"File error: {exc}"}
        verb = "Encrypted" if encrypt else "Decrypted"
        tail = " and removed the source" if req.delete_source else " (source kept)"
        return {"ok": True, "message": f"{verb} {len(done)} file(s){tail}.", "outputs": done}

    @app.post("/api/crypt/encrypt")
    def crypt_encrypt(req: CryptRequest) -> dict[str, Any]:
        return _crypt(req, encrypt=True)

    @app.post("/api/crypt/decrypt")
    def crypt_decrypt(req: CryptRequest) -> dict[str, Any]:
        return _crypt(req, encrypt=False)

    # -- 04 Bound folders: always encrypted on disk, open on double-click ----------------

    bound = BoundFolders(home_dir)
    bind: dict[str, Any] = {"key": None, "auto": True, "note": ""}
    bind_lock = threading.RLock()

    def _assoc() -> str | None:
        try:
            return association_command(classes=assoc_classes)
        except UsbTetherError:
            return None

    def _bind_key() -> bytes:
        """The drive key: cached while the drive stays plugged in."""
        if bind["key"] is None:
            bind["key"] = drive_key(agent, verifier)
        return bind["key"]

    def bind_check() -> None:
        """Background tick: drop the key when the drive leaves; auto-encrypt new plain files."""
        with bind_lock:
            try:
                present = bool(agent.candidates())
            except UsbTetherError:
                return
            if not present:
                if bind["key"] is not None:
                    bind["key"] = None
                    bind["note"] = "Drive removed: the encrypted files can no longer be opened."
                return
            try:
                if bind["key"] is None:
                    _bind_key()
                    sweep(home_dir, bind["key"])
                    bind["note"] = "Drive detected: double-click a .utenc file to open it."
                if bind["auto"]:
                    n = sum(protect_folder(f, bind["key"]) for f in bound.folders() if f.is_dir())
                    if n:
                        bind["note"] = f"Auto-encrypted {n} new file(s)."
            except UsbTetherError as exc:
                bind["note"] = _explain(exc)[0]

    app.state.bind_check = bind_check

    @app.get("/api/bind")
    def bind_state() -> dict[str, Any]:
        folders = []
        for f in bound.folders():
            files = []
            if f.is_dir():
                for p in sorted(f.rglob("*"))[:300]:
                    if p.is_file() and not p.name.endswith(".tmp"):
                        files.append(
                            {
                                "name": p.relative_to(f).as_posix(),
                                "path": str(p),
                                "encrypted": p.name.endswith(SUFFIX),
                            }
                        )
            folders.append({"path": str(f), "exists": f.is_dir(), "files": files})
        return {
            "folders": folders,
            "auto": bind["auto"],
            "note": bind["note"],
            "drive": bind["key"] is not None,
            "association": _assoc(),
            "association_supported": sys.platform == "win32",
        }

    @app.post("/api/bind/add")
    def bind_add(req: BindPath) -> dict[str, Any]:
        folder = Path(req.path).expanduser()
        if not folder.is_dir():
            return {"ok": False, "message": f"Not a folder: {req.path}"}
        bound.add(folder)
        message = f"Bound {folder}."
        if bind["auto"]:
            with bind_lock:
                try:
                    n = protect_folder(folder, _bind_key(), quiet_seconds=0)
                    message += f" Encrypted {n} file(s)."
                except UsbTetherError as exc:
                    message += " Not encrypted yet: " + _explain(exc)[0]
        return {"ok": True, "message": message}

    @app.post("/api/bind/remove")
    def bind_remove(req: BindPath) -> dict[str, Any]:
        bound.remove(Path(req.path))
        return {"ok": True, "message": f"Unbound {req.path}. Its files stay as they are."}

    @app.post("/api/bind/protect")
    def bind_protect(req: BindPath) -> dict[str, Any]:
        """Manual mode: encrypt every plain file in one bound folder now."""
        with bind_lock:
            try:
                n = protect_folder(Path(req.path), _bind_key(), quiet_seconds=0)
            except UsbTetherError as exc:
                return {"ok": False, "message": _explain(exc)[0]}
        return {"ok": True, "message": f"Encrypted {n} file(s)."}

    @app.post("/api/bind/auto")
    def bind_auto(req: BoxAuto) -> dict[str, Any]:
        bind["auto"] = req.auto
        return {"ok": True, "auto": req.auto}

    @app.post("/api/bind/register")
    def bind_register() -> dict[str, Any]:
        try:
            command = register_association(
                default_command(state_home),
                classes=assoc_classes,
                notify=assoc_classes == DEFAULT_CLASSES,
            )
        except UsbTetherError as exc:
            return {"ok": False, "message": str(exc)}
        return {"ok": True, "message": f"Registered. Double-clicking *.utenc runs: {command}"}

    @app.post("/api/bind/unregister")
    def bind_unregister() -> dict[str, Any]:
        try:
            removed = unregister_association(
                classes=assoc_classes, notify=assoc_classes == DEFAULT_CLASSES
            )
        except UsbTetherError as exc:
            return {"ok": False, "message": str(exc)}
        return {"ok": True, "message": "Association removed." if removed else "Not registered."}

    @app.post("/api/bind/open")
    def bind_open(req: BindPath) -> dict[str, Any]:
        """Same as double-clicking the file in Explorer: run ``usbtether open`` detached."""
        target = Path(req.path)
        if not target.name.endswith(SUFFIX) or not target.is_file():
            return {"ok": False, "message": "Not a .utenc file."}
        args = [sys.executable, "-m", "usbtether"]
        if state_home:
            args += ["--home", str(state_home)]
        launcher([*args, "open", str(target)])
        return {"ok": True, "message": f"Opening {target.name}..."}

    if monitor_interval is not None:

        def _bind_loop() -> None:
            while not bind_stop.is_set():
                bind_check()
                bind_stop.wait(monitor_interval)

        bind_stop = threading.Event()
        bind_thread = threading.Thread(target=_bind_loop, name="bind-watch", daemon=True)
        app.state.bind_start = bind_thread.start
        app.state.bind_stop = bind_stop

    # -- Software Guard ------------------------------------------------------------------

    @app.post("/api/guard/start")
    def guard_start(req: GuardStart) -> dict[str, Any]:
        total = max(1, min(req.total_steps, 100))
        try:
            session = authorizer.open_session_local(agent)
        except UsbTetherError as exc:
            message, fatal = _explain(exc)
            return {"started": False, "reason": message, "fatal": fatal, "retry_after_ms": RETRY_MS}
        workflows[session.session_id] = {"total": total, "last_consumed": 0}
        return {
            "started": True,
            "session_id": session.session_id,
            "total_steps": total,
            "drive": session.fingerprint[:12],
        }

    @app.post("/api/guard/authorize")
    def guard_authorize(req: GuardAuthorize) -> dict[str, Any]:
        flow = workflows.get(req.session_id)
        if flow is None:
            raise HTTPException(404, "Unknown demo session")
        if req.step != flow["last_consumed"] + 1:
            raise HTTPException(409, "Steps must be authorized in order")
        if req.step > flow["total"]:
            raise HTTPException(409, "Workflow complete")
        try:
            cap = authorizer.issue_capability_local(
                agent, req.session_id, RESOURCE, f"execute_step:{req.step}"
            )
        except UsbTetherError as exc:
            message, fatal = _explain(exc)
            return {
                "authorized": False,
                "reason": message,
                "fatal": fatal,
                "retry_after_ms": RETRY_MS,
            }
        return {
            "authorized": True,
            "capability": cap.to_dict(),
            "signature_preview": cap.signature[:20] + "...",
        }

    @app.post("/api/guard/consume")
    def guard_consume(req: GuardConsume) -> dict[str, Any]:
        flow = workflows.get(req.session_id)
        if flow is None or req.step != flow["last_consumed"] + 1:
            raise HTTPException(409, "Workflow state mismatch")
        try:
            cap = Capability.from_dict(req.capability)
            if cap.session_id != req.session_id:
                raise AuthorizationError("scope_mismatch", "capability belongs to another session")
            authorizer.consume(cap, resource=RESOURCE, action=f"execute_step:{req.step}")
        except AuthorizationError as exc:
            code = 409 if exc.reason == "capability_used" else 403
            raise HTTPException(code, f"{exc.reason}") from exc
        flow["last_consumed"] = req.step
        return {"consumed": True, "step": req.step, "remaining_steps": flow["total"] - req.step}

    # -- Vault Unlock Lab ----------------------------------------------------------------

    def _live_vault(challenge_id: str) -> dict[str, Any]:
        ch = vault.get(challenge_id)
        if not ch or ch["used"] or time.time() > ch["expires_at"]:
            raise HTTPException(410, "Challenge expired or already used")
        return ch

    @app.post("/api/vault/new")
    def vault_new() -> dict[str, Any]:
        challenge_id = secrets.token_urlsafe(16)
        x = secrets.randbelow(80) + 10
        vault[challenge_id] = {
            "expected": (x * 7 + 13) % 97,
            "used": False,
            "expires_at": time.time() + 180,
        }
        return {
            "challenge_id": challenge_id,
            "question": f"Compute y = ({x} x 7 + 13) mod 97.",
            "x": x,
            "expires_in_seconds": 180,
        }

    @app.post("/api/vault/solve")
    def vault_solve(req: VaultSolve) -> dict[str, Any]:
        ch = _live_vault(req.challenge_id)
        if req.answer != ch["expected"]:
            return {"unlocked": False, "message": "Wrong answer. The vault stays locked."}
        ch["used"] = True
        return {"unlocked": True, "message": "Puzzle solved. Demo vault unlocked."}

    @app.post("/api/vault/usb")
    def vault_usb(req: VaultUsb) -> dict[str, Any]:
        ch = _live_vault(req.challenge_id)
        try:
            result = verifier.authenticate(agent, f"vault-unlock:{req.challenge_id}")
        except UsbTetherError as exc:
            return {"unlocked": False, "message": _explain(exc)[0]}
        if not result.ok:
            reason = result.reason.value if result.reason else "failed"
            return {"unlocked": False, "message": f"USB check failed: {reason}"}
        ch["used"] = True
        return {"unlocked": True, "message": "USB challenge-response accepted. Vault unlocked."}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="usbtether web demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port", type=int, default=8000, help="first port to try (next free one is used)"
    )
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(
            "refusing to bind to a non-loopback address: the demo has no authentication"
        )
    import socket

    import uvicorn

    port = args.port
    for candidate in range(args.port, args.port + 20):
        with socket.socket(socket.AF_INET6 if ":" in args.host else socket.AF_INET) as sock:
            if sock.connect_ex((args.host, candidate)) != 0:  # nothing is listening there
                port = candidate
                break
    else:
        raise SystemExit(f"no free port in {args.port}-{args.port + 19}")
    if port != args.port:
        print(f"port {args.port} is busy; using {port}")
    print(f"Open http://{args.host}:{port}")
    uvicorn.run(create_app(), host=args.host, port=port)


if __name__ == "__main__":
    main()
