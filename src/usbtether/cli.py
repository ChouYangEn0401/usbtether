"""Command line interface: ``usbtether`` or ``python -m usbtether``."""

from __future__ import annotations

import argparse
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
from .probe import DeviceProbe, default_probe
from .registry import Registry
from .verifier import Verifier

EXIT_OK, EXIT_FAILED, EXIT_PLATFORM = 0, 1, 3


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
        probe(), reg, args.mount, label=args.label, passphrase=passphrase, overwrite=args.force
    )
    print(f"Enrolled {args.mount}")
    print(f"  token id   : {result.token.token_id}")
    print(f"  device     : {result.device.vendor_id}:{result.device.product_id}")
    print(f"  protected  : {'passphrase' if passphrase else 'no passphrase'}")
    for old in result.revoked:
        print(f"  revoked    : {old} (replaced)")
    print("A challenge-response self-test passed.")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace, probe: Callable[[], DeviceProbe], reg: Registry) -> int:
    agent = Agent(probe(), passphrase=lambda: _prompt_passphrase(confirm=False))
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
    print(f"Revoked {entry.token_id} at {entry.revoked_at}")
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
    p.add_argument("--passphrase", action="store_true", help="encrypt the private key (prompts)")
    p.add_argument("--force", action="store_true", help="re-enroll; revokes the previous token")
    p.set_defaults(func=_cmd_enroll)

    p = sub.add_parser("verify", help="run a challenge-response against a plugged-in token")
    p.add_argument("mount", nargs="?", help="drive to use (default: the only enrolled drive)")
    p.set_defaults(func=_cmd_verify)

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
