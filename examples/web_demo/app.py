"""usbtether web demo.

A small FastAPI app that exercises the library end to end:

* **USB Authentication**: enroll the drive and verify it from the page (what the CLI's
  ``enroll`` and ``verify`` do), so the other two experiments have something to work with.
* **Software Guard**: a 12-step workflow. Every step needs a fresh challenge-response with
  the enrolled USB drive and yields a single-use, scoped, 8-second capability. Unplugging the
  drive revokes the session.
* **Vault Unlock Lab**: unlock a fictional vault either by solving a puzzle or with a
  USB-backed challenge-response bound to that one vault challenge.

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
import os
import secrets
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
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
from usbtether.probe import DeviceProbe, default_probe
from usbtether.registry import Registry, default_home
from usbtether.secretstore import HostSecretStore
from usbtether.vault import SUFFIX, drive_key, encrypt_file, lock_folder, unlock_folder
from usbtether.verifier import Verifier

RESOURCE = "demo-workflow"
RETRY_MS = 2500
MAX_UPLOAD = 20 * 1024 * 1024
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
    vault_dir: Path | None = None,
) -> FastAPI:
    """Build the app. ``monitor_interval=None`` disables the background thread (for tests)."""
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
            app.state.box_start()
        try:
            yield
        finally:
            monitor.stop()
            if monitor_interval is not None:
                app.state.box_stop.set()

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

    # -- File Vault ----------------------------------------------------------------------

    box_dir = vault_dir or (default_home() / "web-vault")
    box_dir.mkdir(parents=True, exist_ok=True)
    box: dict[str, Any] = {"key": None, "auto": True, "note": ""}
    box_lock = threading.RLock()

    def _box_path(name: str) -> Path:
        """Resolve a user-supplied relative path inside the vault folder (no escaping)."""
        parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
        if not parts or any(p == ".." or ":" in p for p in parts):
            raise HTTPException(400, "Invalid file name")
        target = box_dir.joinpath(*parts)
        if box_dir.resolve() not in target.resolve().parents:
            raise HTTPException(400, "Invalid file name")
        return target

    def box_unlock() -> str:
        with box_lock:
            key = drive_key(agent, verifier)
            result = unlock_folder(box_dir, key)
            box["key"] = key
            return f"Unlocked {result.changed} file(s)."

    def box_lock_now() -> str:
        with box_lock:
            key = box["key"] or drive_key(agent, verifier)
            result = lock_folder(box_dir, key)
            box["key"] = None
            return f"Locked {result.changed} file(s)."

    def box_check() -> None:
        """Auto behaviour: lock when the drive is gone; unlock when it appears (if auto)."""
        with box_lock:
            try:
                present = bool(agent.candidates())
            except UsbTetherError:
                return
            try:
                if not present and box["key"] is not None:
                    box["note"] = "Drive removed: " + box_lock_now()
                elif present and box["key"] is None and box["auto"]:
                    box["note"] = "Drive detected: " + box_unlock()
            except UsbTetherError as exc:
                box["note"] = _explain(exc)[0]

    app.state.box_check = box_check

    @app.get("/api/box")
    def box_state() -> dict[str, Any]:
        files = [
            {
                "name": p.relative_to(box_dir).as_posix(),
                "size": p.stat().st_size,
                "encrypted": p.name.endswith(SUFFIX),
            }
            for p in sorted(box_dir.rglob("*"))
            if p.is_file() and not p.name.endswith(".tmp")
        ]
        return {
            "unlocked": box["key"] is not None,
            "auto": box["auto"],
            "note": box["note"],
            "folder": str(box_dir),
            "files": files,
        }

    @app.post("/api/box/unlock")
    def box_unlock_api() -> dict[str, Any]:
        try:
            return {"ok": True, "message": box_unlock()}
        except UsbTetherError as exc:
            return {"ok": False, "message": _explain(exc)[0]}

    @app.post("/api/box/lock")
    def box_lock_api() -> dict[str, Any]:
        try:
            return {"ok": True, "message": box_lock_now()}
        except UsbTetherError as exc:
            return {"ok": False, "message": _explain(exc)[0]}

    @app.post("/api/box/auto")
    def box_auto(req: BoxAuto) -> dict[str, Any]:
        box["auto"] = req.auto
        return {"ok": True, "auto": req.auto}

    @app.put("/api/box/file")
    async def box_upload(request: Request, name: str) -> dict[str, Any]:
        target = _box_path(name)
        data = await request.body()
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "File too large for the demo (limit 20 MB)")
        with box_lock:
            try:
                # Needs the drive: the file is encrypted at once if the box is locked.
                key = box["key"] or drive_key(agent, verifier)
            except UsbTetherError as exc:
                return {"ok": False, "message": _explain(exc)[0]}
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if box["key"] is None:
                encrypt_file(target, key)
        return {"ok": True, "message": f"Stored {name}" + ("" if box["key"] else " (encrypted)")}

    @app.get("/api/box/file")
    def box_download(name: str) -> Response:
        target = _box_path(name)
        if box["key"] is None or not target.is_file() or target.name.endswith(SUFFIX):
            raise HTTPException(403, "The vault is locked")
        return Response(target.read_bytes(), media_type="application/octet-stream")

    @app.delete("/api/box/file")
    def box_delete(name: str) -> dict[str, Any]:
        target = _box_path(name)
        if not target.is_file():
            raise HTTPException(404, "No such file")
        target.unlink()
        return {"ok": True}

    if monitor_interval is not None:

        def _box_loop() -> None:
            while not box_stop.is_set():
                box_check()
                box_stop.wait(monitor_interval)

        box_stop = threading.Event()
        box_thread = threading.Thread(target=_box_loop, name="vault-watch", daemon=True)
        app.state.box_start = box_thread.start
        app.state.box_stop = box_stop

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
