# Usage guide

A step-by-step guide for Windows (Linux notes at the end of each step where they differ),
plus day-to-day management and troubleshooting. Traditional Chinese: [usage.zh-TW.md](usage.zh-TW.md).

## 1. Install

You need Python 3.10 or newer. From the repository folder:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements-demo.txt      # library + CLI + web demo
```

* `requirements.txt` installs only the library and CLI; `requirements-dev.txt` adds the test
  and lint tools.
* If PowerShell refuses to run `activate` (execution policy), run
  `Set-ExecutionPolicy -Scope Process RemoteSigned` first, or use the classic Command Prompt.
* You can also skip activation and call `.venv\Scripts\usbtether.exe` directly.

On Linux use `python3 -m venv .venv && source .venv/bin/activate`.

## 2. Check that your drive is usable

Plug the drive in and run:

```
usbtether devices
```

```
[1] 0781:5567  SanDisk Cruzer Blade USB Device
    serial   : 4C530001230101117333  (good)
    mounted  : E:\
    bindable : yes
```

`bindable : yes` means the drive reports a real serial number and can be enrolled.
`bindable : NO` means it reports none, a placeholder, or a number Windows made up from the
port; usbtether refuses such drives because it could not tell one unit from another. Try
another drive. If you have two drives of the same model, check that their serials differ.

## 3. Enroll (once per drive)

```
usbtether enroll E: --label "my key" --passphrase
```

* `E:` is the drive letter *now*. The letter is not part of the identity, so it may change later.
* `--passphrase` encrypts the private key on the drive and asks you for a passphrase twice.
  Without it, anyone holding the drive holds the credential. **There is no passphrase
  recovery**; if you forget it, enroll again with `--force`.
* `--label` is a free-text note shown by `usbtether list`.

What happens: a key pair is created on the drive in a `.usbtether` folder; the public key and
the drive's hardware fingerprint are saved on **this computer**; a real challenge-response is
run as a self-test. Only `A challenge-response self-test passed.` means success. Any failure
removes everything it wrote.

The drive still works for normal files. Just do not delete or edit `.usbtether`.

## 4. Verify

```
usbtether verify
```

`OK  token <id>` means: the right key, on the right physical drive, right now. If several
enrolled drives are plugged in, name one: `usbtether verify E:`.

If the key is passphrase-protected you are asked for it (only then).

## 5. Check that copying does not work

With a second flash drive `F:`:

```
xcopy /E /I E:\.usbtether F:\.usbtether
usbtether verify F:
```

Expected: `FAILED  device_mismatch`. The key is valid, but it is not on the drive it was enrolled
on. (A drive that reports the same USB descriptor as the original would pass; see
[threat-model.md](threat-model.md).)

## 6. Use it in your own program

```python
from usbtether import Agent, Authorizer, PresenceMonitor, Registry, Verifier, default_probe

probe = default_probe()
authorizer = Authorizer(Verifier(Registry.default()))
agent = Agent(probe)

session = authorizer.open_session_local(agent)       # authenticate once, at the start
with PresenceMonitor(probe, authorizer):             # unplugging revokes the session
    cap = authorizer.issue_capability_local(         # fresh challenge for this operation
        agent, session.session_id, resource="database", action="write")
    authorizer.consume(cap, resource="database", action="write")   # single use
    do_the_sensitive_thing()
```

* A **session** grants nothing by itself. Every protected operation needs its own
  capability, which needs a fresh challenge-response with the drive.
* A capability works once, for one `(resource, action)`, for 8 seconds.
* Failures raise `usbtether.UsbTetherError` (no drive, wrong drive, locked key, ...) or
  `usbtether.AuthorizationError` (carries a stable `.reason`, for example `session_inactive`,
  `capability_used`, `device_mismatch`).
* Protected key? Pass `Agent(probe, passphrase=b"...")`, or a callable returning the passphrase
  (it is called only when the key is actually encrypted).

A complete, tested example: [examples/sdk_quickstart.py](../examples/sdk_quickstart.py).

## 7. Web demo

```
python examples\web_demo\app.py
```

Open <http://127.0.0.1:8000>. For a passphrase-protected key set the variable first:
`$env:USBTETHER_PASSPHRASE="..."` (PowerShell) or `set USBTETHER_PASSPHRASE=...` (cmd).
Details: [examples/web_demo/README.md](../examples/web_demo/README.md).

## 8. Day-to-day management

| Goal | Command |
|---|---|
| List enrolled tokens | `usbtether list` |
| Revoke a token (drive lost or stolen) | `usbtether revoke <token id>` (ids come from `list`) |
| Enroll the same drive again | `usbtether enroll E: --force` (the previous token is revoked) |
| Pick one of several enrolled drives | `usbtether verify E:` |
| Use another state folder | `--home <dir>` or the `USBTETHER_HOME` variable |

**Lost or stolen drive.** Revoke it: `usbtether revoke <id>`. It stops working on this
computer immediately. Revocation is **not synchronised**: repeat it on every computer that
holds a copy of the registry.

**Reformatted or wiped drive.** The token is gone from the drive but this computer still
remembers it. Run `usbtether enroll E: --force`.

**Forgot the passphrase.** Nothing can recover the key. `usbtether enroll E: --force` replaces
it with a new one (this works because it never needs the old key).

**One drive on several computers.** Each computer decides from its own registry. The drive's
hardware fingerprint is the same on every computer, so copy the registry file from the
computer where you enrolled to the same place on the other one (see section 9). There is no
automatic sync. Do *not* run `enroll --force` on the second computer: that would replace the
key on the drive and break the first.

## 9. Where things are stored

| What | Where |
|---|---|
| Private key, token description | on the drive: `<drive>\.usbtether\private_key.pem`, `token.json` |
| Public keys, drive fingerprints, revocations | Windows: `%APPDATA%\usbtether\registry.json`; Linux: `~/.local/share/usbtether/registry.json` |
| Sessions, capabilities, challenges | process memory only; gone when the program exits |

Treat `registry.json` like a credential store (whoever can write it can enroll tokens), and
never commit `.usbtether/` or `registry.json` to version control (the repository's
`.gitignore` already excludes them).

## 10. Exit codes (CLI)

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the operation failed (verification failed, refused to enroll, ...) |
| 2 | bad command-line usage |
| 3 | the platform or USB query failed (no PowerShell, unsupported OS) |

## 11. Troubleshooting

| You see | Meaning and fix |
|---|---|
| `No USB mass-storage devices found.` | Nothing detected. Re-plug, try another port, wait a few seconds after plugging. |
| `bindable : NO` / `error: this drive cannot be bound: its serial number is ...` | The drive has no usable serial. Use another drive. |
| `error: no USB drive is mounted at 'F:'` | Wrong letter, or the drive is not mounted. Check `usbtether devices`. |
| `error: no USB drive with a usbtether token is plugged in` | The drive is absent or not enrolled. Enroll it (section 3). |
| `error: several enrolled drives are plugged in (...)` | Name one: `usbtether verify E:`. |
| `error: this drive is already enrolled; ... (--force)` | Add `--force` to enroll again (revokes the old token). |
| `FAILED  device_mismatch` | The token is on a different physical drive than the enrolled one (a copy, or a different stick). |
| `FAILED  unknown_token` | This computer's registry has no entry for the token: enrolled elsewhere, or the registry was deleted. Copy `registry.json` or enroll again. |
| `FAILED  token_revoked` | The token was revoked on this computer. Enroll again with `--force`. |
| `FAILED  device_unsupported` | The drive reported no usable serial. |
| `FAILED  bad_signature` | The key does not match the registry (replaced or corrupted). Enroll again. |
| `error: wrong passphrase or corrupt private key` | Retype the passphrase; if forgotten, see section 8. |
| `error: could not run PowerShell: ...` / `PowerShell exited with ...` | `powershell.exe` is missing, blocked by policy, or slow. Run `powershell -NoProfile -Command "Get-CimInstance Win32_DiskDrive"` to see whether it works at all. |
| `error: usbtether has no USB probe for platform 'darwin'` | Only Windows and Linux are supported. |
| `error: cannot read registry ...` | `registry.json` is corrupt or unreadable. Restore a copy or delete it and re-enroll. |

If `usbtether devices` is wrong for your drive, open a *Drive report* issue and paste
`usbtether devices --json --redact` (serial numbers are masked).

## 12. FAQ

**Can I keep using the drive for files?** Yes. The token is two small files in `.usbtether`.
Do not delete the folder.

**Does the drive letter matter?** No. It may change between plugs and computers.

**Does it matter which USB port I use?** No, for drives with a real serial number.

**Is it safe against copying the drive?** Against casual copying, yes. Not against someone who
can make a device report the same USB descriptor, nor against malware on your computer. Read
[threat-model.md](threat-model.md) before relying on it.
