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
usbtether enroll E: --label "my key" --remember
```

* `E:` is the drive letter *now*. The letter is not part of the identity, so it may change later.
* `--label` is a free-text note shown by `usbtether list`.
* The protection option decides how the private key on the drive is stored:

| Option | Typing | What it means |
|---|---|---|
| `--remember` (**recommended on your own computer**) | never | The key is encrypted with a random secret that is kept on **this computer** (Windows DPAPI, bound to your Windows account), never on the drive. Plug in and use. The drive cannot sign anything without this computer's secret. It unlocks only on this computer and account. |
| `--passphrase` | every use | The key is encrypted with a passphrase you type twice now and on every use. Works on any computer. **There is no recovery**; if you forget it, enroll again with `--force`. |
| *(neither)* | never | The key is stored unencrypted. Anyone who holds the drive holds the key. |

What happens: a key pair is created on the drive in a `.usbtether` folder; the public key and
the drive's hardware fingerprint are saved on **this computer**; a real challenge-response is
run as a self-test. Only `A challenge-response self-test passed.` means success. Any failure
removes everything it wrote, including a remembered secret.

The drive still works for normal files. Just do not delete or edit `.usbtether`.

## 4. Verify

```
usbtether verify
```

`OK  token <id>` means: the right key, on the right physical drive, right now. If several
enrolled drives are plugged in, name one: `usbtether verify E:`.

With `--remember` nothing is asked. With `--passphrase` you are asked for the passphrase
(only then).

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

session = authorizer.open_session_local(agent)  # authenticate once, at the start
with PresenceMonitor(probe, authorizer):  # unplugging revokes the session
    cap = authorizer.issue_capability_local(  # fresh challenge for this operation
        agent, session.session_id, resource="database", action="write"
    )
    authorizer.consume(cap, resource="database", action="write")  # single use
    do_the_sensitive_thing()
```

* A **session** grants nothing by itself. Every protected operation needs its own
  capability, which needs a fresh challenge-response with the drive.
* A capability works once, for one `(resource, action)`, for 8 seconds.
* Failures raise `usbtether.UsbTetherError` (no drive, wrong drive, locked key, ...) or
  `usbtether.AuthorizationError` (carries a stable `.reason`, for example `session_inactive`,
  `capability_used`, `device_mismatch`).
* Protected key? A key enrolled with `--remember` unlocks automatically (the agent consults the
  host secret store first). For a `--passphrase` key pass `Agent(probe, passphrase=b"...")`, or a
  callable returning the passphrase (called only when the key is actually encrypted).

A complete, tested example: [examples/sdk_quickstart.py](../examples/sdk_quickstart.py).

## 7. Web demo

```
python examples\web_demo\app.py
```

Open <http://127.0.0.1:8000>. A key enrolled with `--remember` just works. For a `--passphrase` key set the variable first:
`$env:USBTETHER_PASSPHRASE="..."` (PowerShell) or `set USBTETHER_PASSPHRASE=...` (cmd).
Details: [examples/web_demo/README.md](../examples/web_demo/README.md).

## 7b. Encrypted files: double-click to open

Keep files encrypted on disk and open them only while the drive is plugged in.

**Easiest: the desktop app.** Build or get `usbtether-setup-<version>.exe` and install it (see
[building.md](building.md) and [packaging/README.md](../packaging/README.md)). It registers double-click for `.utenc` and adds
a small panel that waits for the drive and keeps *bound folders* encrypted; tick *Start with
Windows* to have it always running. No web page needed.

**From the console** (without the installer):

```
usbtether register                      # once: double-clicking *.utenc runs "usbtether open"
usbtether app                           # the same panel, started from Python
usbtether vault lock D:\Secret          # encrypt a whole folder by hand
```

Now double-click `D:\Secret\report.docx.utenc` in Explorer. `usbtether open` checks the
drive, decrypts the file into `%APPDATA%\usbtether\open\<id>\report.docx`, and opens it in
Word. Every save is encrypted back over `report.docx.utenc` within about a second. Pull the
drive out and the working copy is deleted. Without the drive a message box says so and nothing
opens. `usbtether register --remove` undoes the registration (it only touches
`HKCU\Software\Classes\.utenc` and `usbtether.encfile`; no admin needed).

| Situation | What happens |
|---|---|
| Double-click does nothing / "choose an app" appears | not registered: tick *Double-click a .utenc file* in the panel, or `usbtether register`. If you once chose "Always use this app" for `.utenc`, Windows keeps that choice: pick *usbtether* in *Open with > Choose another app > Always* |
| Editor keeps the file locked (Word, Excel) | working copy stays until the drive is pulled, or until you close it and 30 min pass without a save |
| Editor keeps no lock (Notepad) | "closed" cannot be detected: the copy goes when the drive is pulled or after 30 min without a save (`--idle-timeout` to change) |
| You pull the drive (or eject it) while the file is open | the copy is deleted at once if nothing holds it; if a program does, a message asks you to close it, saves made meanwhile are still encrypted back (the key stays in memory only for that), and the copy is deleted the moment it is closed |
| You rename or move the folder while a file is open | the next save goes to the file's new place: it is found by name and its exact encrypted bytes near the old place or in a bound folder. The old folder is never recreated |
| The `.utenc` was deleted or moved far away while open | the save is not lost: it is written, still encrypted, to `%APPDATA%\usbtether\recovered\<time>\` |
| You rename a bound folder | the panel follows it (folders are tracked by their file id) and keeps protecting it |
| Ejecting says the drive is in use | the helper and the panel work from `%APPDATA%\usbtether`, never from the drive; another program has a file on the drive open |
| The helper is killed | the next `usbtether open` (or the panel) syncs unsaved changes back and deletes the leftover, once no program holds it |
| A program (`.exe`) in a bound folder | opens from the working copy alone, without the files next to it, so most programs fail: bound folders are for documents |
| You re-enroll with `--force` | **files encrypted with the old key can never be opened again** (the key comes from the token) |

Limits: while a file is open its plain copy is on disk where any program running as you can
read it, and the key is in the helper's memory. Bound folders are auto-encrypted only while
the panel (or the web demo) runs. Presence while unlocked is checked by looking for the token
folder on the verified drive letter (instant, no 2 s probe).

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

**Forgot the passphrase, or lost the remembered secret** (reinstalled Windows, new Windows
account). Nothing can recover the key. `usbtether enroll E: --force` replaces it with a new
one (this works because it never needs the old key).

**Change how the key is protected.** Enroll again: `usbtether enroll E: --remember --force`
(or `--passphrase`, or neither). The previous token is revoked.

**One drive on several computers.** Each computer decides from its own registry. The drive's
hardware fingerprint is the same on every computer, so copy the registry file from the
computer where you enrolled to the same place on the other one (see section 9). There is no
automatic sync. Do *not* run `enroll --force` on the second computer: that would replace the
key on the drive and break the first. A `--remember` key unlocks only where it was enrolled; for
several computers use `--passphrase` (or no encryption).

## 9. Where things are stored

| What | Where |
|---|---|
| Private key, token description | on the drive: `<drive>\.usbtether\private_key.pem`, `token.json` |
| Public keys, drive fingerprints, revocations | Windows: `%APPDATA%\usbtether\registry.json`; Linux: `~/.local/share/usbtether/registry.json` |
| Secrets for `--remember` keys | Windows: `%APPDATA%\usbtether\secrets\<token id>.bin`, sealed with DPAPI (only your Windows account can read it); Linux: the same path, owner-only file permissions |
| Sessions, capabilities, challenges | process memory only; gone when the program exits |
| Bound folders (web demo) | `%APPDATA%\usbtether\bound.json` |
| Working copies of opened `.utenc` files | `%APPDATA%\usbtether\open\<id>\` while open; removed afterwards |
| Double-click association | `HKCU\Software\Classes\.utenc` and `HKCU\Software\Classes\usbtether.encfile` |

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
| Web demo: `The key is passphrase-protected. Enroll it again with 'usbtether enroll <drive> --remember --force' ...` | The key needs a passphrase the demo cannot ask for. Enroll again with `--remember --force`, or set `USBTETHER_PASSPHRASE` and restart. |
| `error: the private key is passphrase-protected` | A library call found an encrypted key and no secret. Enroll with `--remember`, or pass `passphrase=` to `Agent`. |
| `error: cannot unprotect the stored secret (was it saved by another Windows user?)` | The `--remember` secret was saved under a different Windows account or machine. Enroll again with `--remember --force` on this account. |
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
