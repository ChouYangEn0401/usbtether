"""Command line interface: ``usbtether`` or ``python -m usbtether``."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from . import __version__
from .agent import Agent
from .device import UsbDevice
from .enrollment import enroll
from .errors import ProbeError, UsbTetherError
from .opener import (
    FolderGuard,
    association_command,
    default_command,
    open_encrypted,
    register_association,
    unregister_association,
)
from .probe import DeviceProbe, default_probe
from .registry import Registry, default_home
from .secretstore import HostSecretStore, default_secret_store
from .vault import VaultWatcher, drive_key, lock_folder, unlock_folder
from .verifier import Verifier

EXIT_OK, EXIT_FAILED, EXIT_PLATFORM = 0, 1, 3

_PROTECTION = {
    "none": "no passphrase",
    "passphrase": "passphrase",
    "host-secret": "secret stored on this computer",
}


def _store(args: argparse.Namespace) -> HostSecretStore:
    return default_secret_store(Path(args.home) if args.home else None)


def _redact(serial: str | None) -> str | None:
    if not serial:
        return serial
    return serial if len(serial) <= 6 else f"{serial[:2]}{'*' * (len(serial) - 4)}{serial[-2:]}"


def _device_dict(device: UsbDevice, redact: bool) -> dict[str, object]:
    return {
        "vendor_id": device.vendor_id,
        "product_id": device.product_id,
        "serial": _redact(device.serial) if redact else device.serial,
        "serial_quality": device.serial_quality.value,
        "bindable": device.is_bindable,
        "product": device.product,
        "capacity": device.capacity,
        "volumes": [
            {
                "mount_point": v.mount_point,
                "filesystem": v.filesystem,
                "volume_serial": None if redact else v.volume_serial,
                "label": v.label,
            }
            for v in device.volumes
        ],
    }


def _prompt_passphrase(*, confirm: bool) -> bytes:
    first = getpass.getpass("Passphrase for the USB private key: ")
    if not first:
        raise UsbTetherError("an empty passphrase is not allowed")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise UsbTetherError("passphrases do not match")
    return first.encode("utf-8")


def _cmd_devices(args: argparse.Namespace, probe: Callable[[], DeviceProbe], _: Registry) -> int:
    devices = probe().list_devices()
    if args.json:
        print(json.dumps([_device_dict(d, args.redact) for d in devices], indent=2))
        return EXIT_OK
    if not devices:
        print("No USB mass-storage devices found.")
        return EXIT_OK
    for index, device in enumerate(devices, 1):
        info = _device_dict(device, args.redact)
        print(f"[{index}] {device.vendor_id}:{device.product_id}  {device.product or '(unnamed)'}")
        print(f"    serial   : {info['serial'] or '-'}  ({device.serial_quality.value})")
        mounts = ", ".join(v.mount_point or "(unmounted)" for v in device.volumes) or "-"
        print(f"    mounted  : {mounts}")
        if device.is_bindable:
            print("    bindable : yes")
        else:
            print("    bindable : NO - usbtether needs a real hardware serial number")
    return EXIT_OK


def _cmd_enroll(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    passphrase = _prompt_passphrase(confirm=True) if args.passphrase else None
    result = enroll(
        probe(),
        reg,
        args.mount,
        label=args.label,
        passphrase=passphrase,
        remember=args.remember,
        secret_store=_store(args),
        overwrite=args.force,
    )
    print(f"Enrolled {args.mount}")
    print(f"  token id   : {result.token.token_id}")
    print(f"  device     : {result.device.vendor_id}:{result.device.product_id}")
    print(f"  protected  : {_PROTECTION[result.protection]}")
    if result.protection == "host-secret":
        print("  note       : unlocks automatically on this computer only")
    for old in result.revoked:
        print(f"  revoked    : {old} (replaced)")
    print("A challenge-response self-test passed.")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    agent = Agent(
        probe(),
        passphrase=lambda: _prompt_passphrase(confirm=False),
        secret_store=_store(args),
    )
    result = Verifier(reg).authenticate(agent, "cli-verify", args.mount)
    if result.ok:
        print(f"OK  token {result.token_id}")
        for warning in result.warnings:
            print(f"warning: {warning}")
        return EXIT_OK
    print(f"FAILED  {result.reason.value if result.reason else 'unknown'}", file=sys.stderr)
    if result.detail:
        print(f"  {result.detail}", file=sys.stderr)
    return EXIT_FAILED


def _cmd_list(_: argparse.Namespace, __: Callable[[], DeviceProbe], reg: Registry) -> int:
    entries = reg.entries()
    if not entries:
        print("No tokens enrolled.")
        return EXIT_OK
    for e in entries:
        dev = e.device
        print(
            f"{e.token_id}  {e.status:<7}  {dev.get('vendor_id')}:{dev.get('product_id')}  "
            f"fp={e.fingerprint[:12]}  {e.enrolled_at}  {e.label or ''}".rstrip()
        )
    return EXIT_OK


def _cmd_revoke(args: argparse.Namespace, _: Callable[[], DeviceProbe], reg: Registry) -> int:
    entry = reg.revoke(args.token_id)
    with contextlib.suppress(UsbTetherError):  # drop the remembered unlock secret, if any
        _store(args).delete(entry.token_id)
    print(f"Revoked {entry.token_id} at {entry.revoked_at}")
    return EXIT_OK


def _cmd_vault(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    folder = Path(args.folder)
    if not folder.is_dir():
        raise UsbTetherError(f"{folder} is not a folder")
    agent = Agent(
        probe(),
        passphrase=lambda: _prompt_passphrase(confirm=False),
        secret_store=_store(args),
    )
    verifier = Verifier(reg)
    if args.action == "watch":
        print(f"Watching {folder}: plug the drive in to unlock, pull it out to lock. Ctrl+C stops.")
        VaultWatcher(folder, agent, verifier, on_event=print).run(args.interval)
        return EXIT_OK
    key = drive_key(agent, verifier)
    if args.action == "lock":
        result = lock_folder(folder, key)
        print(f"Locked {result.changed} file(s); {result.skipped} already locked.")
    else:
        result = unlock_folder(folder, key)
        print(f"Unlocked {result.changed} file(s); {result.skipped} already plain.")
    return EXIT_OK


def _tell(message: str) -> None:
    """Report an error where the user can see it, even when launched without a console."""
    if sys.stderr is not None and sys.stderr.isatty():
        print(f"error: {message}", file=sys.stderr)
    elif sys.platform == "win32":
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, "usbtether", 0x10)


def _passphrase_source() -> Callable[[], bytes]:
    """Ask on the console, or with a small dialog when there is no console (double-click)."""
    if sys.stdin is not None and sys.stdin.isatty():
        return lambda: _prompt_passphrase(confirm=False)

    def ask() -> bytes:
        from .desktop import ask_passphrase

        return ask_passphrase()

    return ask


def _cmd_app(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    from .desktop import run_app

    home = Path(args.home) if args.home else default_home()
    agent = Agent(probe(), passphrase=_passphrase_source(), secret_store=_store(args))
    return run_app(agent, Verifier(reg), home, minimized=args.minimized)


def _cmd_open(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    home = Path(args.home) if args.home else default_home()
    agent = Agent(probe(), passphrase=_passphrase_source(), secret_store=_store(args))
    guard = FolderGuard(agent, Verifier(reg), home)
    try:
        key = guard.ensure_key()  # verifies the drive, then sweeps crash leftovers
    except UsbTetherError as exc:
        _tell(
            f"Cannot open {Path(args.file).name}: {exc}\nPlug in the enrolled drive and try again."
        )
        return EXIT_FAILED
    open_encrypted(
        Path(args.file),
        key,
        home,
        present=guard.still_present,
        idle_timeout=args.idle_timeout,
        on_event=lambda m: print(m, flush=True) if sys.stdout is not None else None,
    )
    return EXIT_OK


def _cmd_register(args: argparse.Namespace, _: Callable[[], DeviceProbe], __: Registry) -> int:
    home = Path(args.home) if args.home else None
    if args.remove:
        print("Removed the .utenc association." if unregister_association() else "Not registered.")
        return EXIT_OK
    register_association(default_command(home))
    print(f"Registered: double-clicking *.utenc runs\n  {association_command()}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usbtether",
        description="Bind sessions to an ordinary USB drive (device-bound Ed25519 token).",
    )
    parser.add_argument("--version", action="version", version=f"usbtether {__version__}")
    parser.add_argument(
        "--home",
        help="state directory (default: %%APPDATA%%\\usbtether or "
        "~/.local/share/usbtether; or $USBTETHER_HOME)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("devices", help="list attached USB drives and their identity quality")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--redact", action="store_true", help="mask serial numbers (for bug reports)")
    p.set_defaults(func=_cmd_devices)

    p = sub.add_parser("enroll", help="write a token to a drive and register it on this host")
    p.add_argument("mount", help="drive letter or mount point, e.g. E: or /media/me/KEY")
    p.add_argument("--label", help="free-text note stored in the registry")
    protection = p.add_mutually_exclusive_group()
    protection.add_argument(
        "--passphrase", action="store_true", help="encrypt the private key (asks every time)"
    )
    protection.add_argument(
        "--remember",
        action="store_true",
        help="encrypt the private key with a secret kept on this computer: no typing here, "
        "useless without this computer",
    )
    p.add_argument("--force", action="store_true", help="re-enroll; revokes the previous token")
    p.set_defaults(func=_cmd_enroll)

    p = sub.add_parser("verify", help="run a challenge-response against a plugged-in token")
    p.add_argument("mount", nargs="?", help="drive to use (default: the only enrolled drive)")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("vault", help="encrypt/decrypt a folder with the key of a plugged-in drive")
    p.add_argument("action", choices=["lock", "unlock", "watch"])
    p.add_argument("folder")
    p.add_argument("--interval", type=float, default=1.0, help="watch: seconds between checks")
    p.set_defaults(func=_cmd_vault)

    p = sub.add_parser(
        "open", help="decrypt a .utenc file, open it, and encrypt it back when you save"
    )
    p.add_argument("file")
    p.add_argument(
        "--idle-timeout",
        type=float,
        default=1800.0,
        help="seconds without a save before the plain copy is deleted (default 1800)",
    )
    p.set_defaults(func=_cmd_open)

    p = sub.add_parser(
        "app", help="the desktop panel: waits for the drive and keeps bound folders encrypted"
    )
    p.add_argument("--minimized", action="store_true", help="start minimised (used at sign-in)")
    p.set_defaults(func=_cmd_app)

    p = sub.add_parser(
        "register", help="Windows: make double-clicking a .utenc file run 'usbtether open'"
    )
    p.add_argument("--remove", action="store_true", help="undo the registration")
    p.set_defaults(func=_cmd_register)

    p = sub.add_parser("list", help="show tokens registered on this host")
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("revoke", help="revoke a token so it can no longer authenticate")
    p.add_argument("token_id")
    p.set_defaults(func=_cmd_revoke)
    return parser


def main(argv: Sequence[str] | None = None, *, probe: DeviceProbe | None = None) -> int:
    args = build_parser().parse_args(argv)
    registry = Registry(Path(args.home) / "registry.json") if args.home else Registry.default()
    get_probe: Callable[[], DeviceProbe] = (lambda: probe) if probe else default_probe
    try:
        return int(args.func(args, get_probe, registry))
    except ProbeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_PLATFORM
    except UsbTetherError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return EXIT_FAILED
