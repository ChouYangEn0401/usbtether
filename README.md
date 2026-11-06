# usbtether

**Bind sessions to an ordinary USB drive.**

[English](README.md) · [繁體中文](README.zh-TW.md)

[![CI](https://github.com/ChouYangEn0401/usbtether/actions/workflows/ci.yml/badge.svg)](https://github.com/ChouYangEn0401/usbtether/actions/workflows/ci.yml)

usbtether turns a plain USB flash drive into a *presence-bound credential*: a program can
require that one specific, previously enrolled drive is plugged in before it opens a session,
and can re-check that on every sensitive step.

* **Device-bound.** The credential is an Ed25519 key on the drive, tied on the host to the
  drive's USB descriptor (vendor id, product id, serial number). Copying the files to another
  flash drive does not produce a working copy.
* **Challenge-response.** Every authentication is a fresh, single-use, purpose-bound challenge
  signed by the token. Nothing is replayable.
* **Short-lived authority.** A session grants nothing by itself. Each protected operation
  needs its own challenge and yields a single-use, scoped capability that expires in seconds.
  Unplugging the drive revokes the session.
* **Plug and use.** `--remember` encrypts the key with a secret kept on *your computer*
  (Windows DPAPI), so there is nothing to type, and the drive cannot sign without that computer.
* **Works with drives you already own.** No special hardware.

> [!IMPORTANT]
> **Security level: convenience-grade.** An ordinary USB drive cannot compute signatures or
> hide a key. usbtether stops *casual copying* of the credential. It does **not** stop an
> attacker who can make another device report the same USB descriptor, nor a compromised host.
> If that matters to you, use a FIDO2/WebAuthn security key. Details: [docs/threat-model.md](docs/threat-model.md).

## Status

Alpha (0.1.x). The protocol, token format and API may change before 1.0.

| Platform | Support |
|---|---|
| Windows 10/11 | Primary target. Discovery uses PowerShell/CIM. Confirmed working on a real Windows machine with one USB 3.0 flash drive (enroll and verify); the parser is unit-tested against recorded output and the script is smoke-tested in CI. Not yet validated across many drives: please report your results. |
| Linux | Experimental (sysfs). Mostly for development and CI. |
| macOS | Not supported. |

Python 3.10+. The only runtime dependency is [`cryptography`](https://cryptography.io/).

## Install

Not on PyPI yet. From a checkout:

```bash
pip install .            # library + CLI
pip install ".[demo]"    # + web demo dependencies
pip install -e ".[dev]"  # development
```

Prefer `requirements` files? They only point at `pyproject.toml`, the single source of truth:
`pip install -r requirements.txt` (library), `requirements-demo.txt` (+ web demo),
`requirements-dev.txt` (development).

## Quick start (CLI)

Step-by-step Windows guide, day-to-day management and troubleshooting: **[docs/usage.md](docs/usage.md)**.

```console
> usbtether devices
[1] 0781:5567  SanDisk Cruzer Blade USB Device
    serial   : 4C530001230101117333  (good)
    mounted  : E:\
    bindable : yes

> usbtether enroll E: --label "desk key" --remember
Enrolled E:
  token id   : 0b6a0c4e-6c67-4b0c-9a58-2a7d1f4a8d11
  device     : 0781:5567
  protected  : secret stored on this computer
  note       : unlocks automatically on this computer only
A challenge-response self-test passed.

> usbtether verify
OK  token 0b6a0c4e-6c67-4b0c-9a58-2a7d1f4a8d11
```

Copy the `.usbtether` folder to another drive and `usbtether verify F:` fails with
`device_mismatch`. `usbtether list` shows enrolled tokens, `usbtether revoke <id>` revokes one.

`usbtether devices` tells you whether your drive is usable. Drives that report no serial
number, or a placeholder, **cannot be enrolled**. Many cheap drives are like that.

## Quick start (library)

```python
from usbtether import Agent, Authorizer, PresenceMonitor, Registry, Verifier, default_probe

probe = default_probe()
authorizer = Authorizer(Verifier(Registry.default()))
agent = Agent(probe)

session = authorizer.open_session_local(agent)  # needs the enrolled drive
with PresenceMonitor(probe, authorizer):  # revokes the session on unplug
    cap = authorizer.issue_capability_local(  # fresh challenge for this action
        agent, session.session_id, resource="database", action="write"
    )
    authorizer.consume(cap, resource="database", action="write")  # single use
```

A complete, tested version is in [examples/sdk_quickstart.py](examples/sdk_quickstart.py).
Errors derive from `usbtether.UsbTetherError`; authorization failures are
`AuthorizationError` with a stable `reason` code.

## Desktop app (Windows)

`packaging\build.ps1` builds `usbtether-setup-<version>.exe`: a per-user installer for a small
panel that waits for the drive, keeps chosen folders encrypted, and makes `.utenc` files open on
double-click while the drive is plugged in (every save is encrypted back). See
[packaging/README.md](packaging/README.md).

## Web demo

An experiment harness (not a deployable service) that exercises the whole flow in a browser:
a 12-step guarded workflow, a vault-unlock lab, one-off encrypt/decrypt of real files, and
bound folders whose files open on double-click only while the drive is plugged in
(`usbtether register` / `usbtether open`, see [docs/usage.md §7b](docs/usage.md)).
See [examples/web_demo](examples/web_demo/README.md).

```bash
pip install ".[demo]"
usbtether enroll E:
python examples/web_demo/app.py        # http://127.0.0.1:8000
```

## How it works

```
 enroll (once)                          authenticate (every time)

 USB drive                               Verifier                     Agent
 +--------------+   public key,         +-----------+   challenge    +-----------+
 | private key  |   drive fingerprint   | registry  | -------------> | reads the |
 | token.json   | -------------------> | (host)    |                | USB drive |
 +--------------+                       |           | <------------- |  and signs|
                                        +-----------+  signed        +-----------+
                                                       response
```

1. **Enroll**: generate a key pair on the drive; store the public key and the drive's
   fingerprint in the *host* registry; self-test; roll back on any failure.
2. **Authenticate**: the verifier issues a challenge; the agent signs it together with what
   it observes about the drive; the verifier checks challenge, token, signature, and that the
   drive's fingerprint equals the enrolled one.
3. **Authorize**: sessions and single-use capabilities on top of (2).

The decisive point: what identifies the drive is stored on the **host**, not on the drive,
so a copy of the drive's files carries a valid key but the wrong hardware identity.

Full specification: [docs/protocol.md](docs/protocol.md) ·
Architecture: [docs/architecture.md](docs/architecture.md) ·
Device identity: [docs/device-identity.md](docs/device-identity.md).

## What it does and does not protect against

| | |
|---|---|
| Copying the token files to another flash drive | stopped |
| Replaying a captured response | stopped |
| Reusing a response for another action | stopped |
| Using a drive without a real serial number | refused |
| Acting after the drive is unplugged | stopped (polling, plus 8 s capability lifetime) |
| A drive that reports the same USB descriptor (reprogrammed controller, virtual device) | **not stopped** |
| Malware on the host | **not stopped** |
| Someone who gets an unprotected drive | **not stopped** until you revoke it; use `--remember` or `--passphrase` |

## Prior art

* **[pam_usb](https://wiki.archlinux.org/title/Pam_usb)** (Linux) authenticates users with
  ordinary USB drives by checking serial, vendor and model, and by rewriting a one-time pad
  on the drive after each login so that a copy goes stale. usbtether follows the same idea
  for Windows and library use; the rolling secret is on the [roadmap](#roadmap).
* **YubiKey, FIDO2/WebAuthn, smart cards, OpenPGP tokens** keep the private key inside
  tamper-resistant hardware. They are the right answer when clones must be impossible.
  usbtether is for when they are not available.

## Roadmap

* Validate the Windows probe on more real drives; collect reports ([docs/device-identity.md](docs/device-identity.md)).
* Rolling secret to *detect* a cloned drive.
* Event-driven removal detection on Windows.
* Signed registry and revocation lists.
* A transport and reference helper for the split agent/verifier deployment.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
Changes: [CHANGELOG.md](CHANGELOG.md).

## Origin

usbtether grew out of a small "USB crypto playground" experiment (capability authorization with
a USB-assisted unlock) whose HMAC check ran in a single process against a copyable key file,
so it proved nothing about the drive. This project replaces that with a device-bound token
and a verifiable exchange.

## License

[MIT](LICENSE)
