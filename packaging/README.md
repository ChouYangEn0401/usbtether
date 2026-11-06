# Windows desktop app and installer

`usbtether-setup-<version>.exe` installs a small desktop panel and makes `.utenc` files open
on double-click. Per-user install (`%LOCALAPPDATA%\Programs\usbtether`), no admin rights.

## For users

1. Run `usbtether-setup-<version>.exe`. Optional tasks: desktop shortcut, *Start usbtether when I
   sign in*.
2. Enroll your drive once if you have not: `usbtether enroll E: --remember` (console CLI,
   `pip install usbtether`) or the web demo's *USB Authentication* tab. The panel itself does
   not enroll.
3. Open **usbtether** from the Start menu. The panel shows:
   * **Status**: amber *Waiting for the USB drive*, green *Unlocked* (drive verified with a
     challenge-response), red *Locked* with the reason (and an *Unlock* button to retry).
   * **Bound folders**: folders kept encrypted. *+ Add folder* encrypts what is in it; with
     *Auto-encrypt* on, any new plain file saved there is encrypted within a few seconds.
     *Encrypt now* does it by hand (Manual mode). *Open* shows the folder in Explorer.
   * **One-off**: encrypt or decrypt chosen files next to the originals, optionally deleting
     the source.
   * **Settings**: auto-encrypt, double-click registration, start with Windows.
4. Double-click any `name.ext.utenc`. With the drive in, it opens in its usual program; every
   save is encrypted back. Without the drive a message says so.

You can pull the drive out at any time and rename or move folders while files are open; see
the table in [docs/usage.md §7b](../docs/usage.md) for exactly what happens. In short: no plain
copy is left behind and no save is lost.

Closing the panel stops auto-encryption only; double-click opening keeps working because it is
a separate process (`usbtether.exe open "<file>"`) started by Explorer.

Uninstall from *Settings > Apps*. It removes the program, the shortcuts, the `.utenc`
association and the sign-in entry. It keeps `%APPDATA%\usbtether` (registry of enrolled drives,
remembered secrets, bound folders): deleting those would make encrypted files unopenable.

## For developers

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

* Installs PyInstaller into the venv, builds `build\dist\usbtether\usbtether.exe` (windowed,
  entry point [usbtether_entry.py](usbtether_entry.py): no arguments = `usbtether app`, any
  other arguments = the CLI), then compiles [usbtether.iss](usbtether.iss) with Inno Setup 6.
* Inno Setup is looked up in `$env:ISCC`, `PATH`, its uninstall registry entry, then the usual
  folders. Install it with `winget install JRSoftware.InnoSetup` if missing.
* Output: `build\installer\usbtether-setup-<version>.exe` (version from `usbtether.__version__`).
* The icon is `src\usbtether\usbtether.ico`, drawn by [make_icon.py](make_icon.py) (standard
  library only); rerun it after changing the design.

| Piece | Where |
|---|---|
| Panel (tkinter) | `src/usbtether/desktop.py` (`usbtether app [--minimized]`) |
| Drive watching, bound folders, auto-encrypt | `FolderGuard` in `src/usbtether/opener.py` (shared with the web demo) |
| Double-click open / save-back / crash cleanup | `open_encrypted`, `sweep` in `opener.py` |
| Association and start-at-sign-in keys | `register_association`, `set_run_at_login` in `opener.py`; the installer writes the same keys |

The executable has no console, so CLI commands run through it print nothing; errors from
`open` are shown in a message box. A passphrase-protected key is asked for in a dialog.
