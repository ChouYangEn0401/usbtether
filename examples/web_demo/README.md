# usbtether web demo

An experiment harness for the library. **Not a deployable service**: no user authentication,
agent and verifier share one process, and it refuses to bind to anything but loopback.

## Run

```bash
pip install ".[demo]"          # from the repository root
usbtether enroll E:            # once; use your drive's letter
python examples/web_demo/app.py
```

Open <http://127.0.0.1:8000>. If the drive's key is passphrase-protected, set
`USBTETHER_PASSPHRASE` before starting.

## What to try

**USB Authentication**: pick your drive, press *Enroll*, then *Verify now*. This is the CLI's
`enroll` and `verify` in the browser; do it first.

**Software Guard**: start the 12-step workflow. Each step performs a fresh challenge-response
and consumes a single-use capability scoped to that step (`demo-workflow` /
`execute_step:<n>`, 8 s). Unplug the drive mid-run: the presence monitor revokes the session
and the workflow stops. Re-plugging does not revive it.

**Vault Unlock Lab**: generate a challenge, then either solve the puzzle or press *USB override*,
which runs a challenge-response whose purpose is bound to that one vault challenge.

The tabs, in order:

| Tab | Purpose |
|---|---|
| 00 USB Authentication | enroll and verify the drive (do this first) |
| 01 Software Guard | per-step challenge-response with single-use capabilities |
| 02 Vault Unlock Lab | a fictional vault: puzzle or USB override |
| 03 Encrypt / Decrypt | one-off jobs on real files anywhere on this computer |
| 04 Bound Folders | folders that stay encrypted; double-click a file to open it |

**Encrypt / Decrypt**: two halves, cyan for encrypt and amber for decrypt. Drop files or
folders on a half, or use *Files…* / *Folder…* (a native Windows dialog, so the real path is
known). *Auto* runs as soon as something arrives; *Manual* queues it until you press the
button. Options per half: delete the source afterwards (on by default), and save *back where it
was* (default) or to *another folder* (default `%APPDATA%\usbtether\encrypted` / `decrypted`).
A browser never reveals where a dropped file lives, so the server looks for it by name, size
and date under Desktop, Downloads, Documents, Pictures, Videos, Music and OneDrive; if that
fails, the page says so and you use the buttons.

**Bound Folders**: drop a folder (or *Choose folder…*) to bind it; its files are encrypted.
*Register* writes the per-user `.utenc` association so double-clicking a file in Explorer runs
`usbtether open` (decrypt to a working copy, open, encrypt every save back, delete the copy
when the drive leaves). The *open* links on the page do the same. *Auto* encrypts any new plain
file saved into a bound folder within a few seconds; *Manual* waits for *Encrypt now*. See
[docs/usage.md §7b](../../docs/usage.md) for the limits.

**Copy test**: copy `E:\.usbtether` to a second flash drive, unplug the original, and try
again. The result is `device_mismatch`. (A drive that reports the same USB descriptor would
pass; see [docs/threat-model.md](../../docs/threat-model.md).)

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/status` | attached drives, whether they are enrolled, recent sessions |
| `POST /api/guard/start` | open a session (needs the drive) |
| `POST /api/guard/authorize` | fresh challenge for one step, returns a capability |
| `POST /api/guard/consume` | spend the capability |
| `POST /api/vault/new`, `/solve`, `/usb` | vault puzzle and USB override |
| `POST /api/crypt/pick` | native file/folder dialog on this machine, returns paths |
| `POST /api/crypt/resolve` | find dropped items on disk by name (+ size, date) |
| `POST /api/crypt/encrypt`, `/decrypt` | `{paths, delete_source, dest: inplace\|custom, dest_dir}` |
| `GET /api/bind` | bound folders, their files, drive and association state |
| `POST /api/bind/add`, `/remove`, `/protect`, `/auto` | manage bound folders and auto mode |
| `POST /api/bind/register`, `/unregister` | the `.utenc` double-click association (Windows) |
| `POST /api/bind/open` | spawn `usbtether open <file>` |

Browsers cannot read USB serial numbers or drive contents, which is why the *server* reads the
drive. For a remote web application you would run the agent on the user's machine as a local
helper; see [docs/architecture.md](../../docs/architecture.md).
