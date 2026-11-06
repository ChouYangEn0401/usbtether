# Building usbtether

[English](building.md) · [繁體中文](building.zh-TW.md)

How to set up a development checkout, run the checks, and build the Windows installer. For
*using* usbtether see [usage.md](usage.md); for the desktop app's user guide see
[packaging/README.md](../packaging/README.md).

## 1. Prerequisites

| Need | For | Notes |
|---|---|---|
| Python 3.10+ (64-bit) | everything | python.org build recommended; it includes tkinter (the desktop panel) |
| Git | the checkout | |
| Inno Setup 6 | the installer only | `winget install JRSoftware.InnoSetup` |
| A USB flash drive with a serial number | trying it for real | `usbtether devices` says whether yours is usable |

## 2. Development setup

```powershell
git clone https://github.com/ChouYangEn0401/usbtether.git
cd usbtether
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

`-e` installs in editable mode: changes under `src/` take effect without reinstalling.

## 3. Checks (run before every commit)

```powershell
ruff check .
ruff format --check .
mypy
pytest
```

CI runs the same on Windows and Linux (`.github/workflows/ci.yml`). Tests never touch your
real state folder (`USBTETHER_HOME` is redirected) and never the real file association (a
scratch registry key is used).

## 4. Run from source

```powershell
usbtether devices                    # is the drive usable?
usbtether enroll E: --remember       # once per drive
usbtether app                        # the desktop panel
python examples\web_demo\app.py      # the web demo, http://127.0.0.1:8000
```

## 5. Build the Windows installer

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

What it does:

1. Installs PyInstaller and the package into `.venv` (or the `python` on `PATH`).
2. Builds `build\dist\usbtether\usbtether.exe` with PyInstaller: one folder, no console window,
   entry point [packaging/usbtether_entry.py](../packaging/usbtether_entry.py) (no arguments
   opens the panel; anything else is the normal CLI, e.g. `usbtether.exe open "<file>"`).
3. Finds Inno Setup (`$env:ISCC`, `PATH`, its uninstall registry entry, the usual folders) and
   compiles [packaging/usbtether.iss](../packaging/usbtether.iss).

Output: `build\installer\usbtether-setup-<version>.exe` (about 13 MB). The version comes from
`src/usbtether/__init__.py`.

The installer is per user (`%LOCALAPPDATA%\Programs\usbtether`, no admin). It shows the
license, writes the `.utenc` association and, if chosen, a desktop shortcut and the sign-in
entry. Uninstalling removes those and keeps `%APPDATA%\usbtether` on purpose.

### Smoke test before publishing

1. Install the new `usbtether-setup-<version>.exe`.
2. Start *usbtether* from the Start menu: the panel shows *Waiting for the USB drive*.
3. Plug in an enrolled drive: it turns green (*Unlocked*).
4. *+ Add folder* on a test folder with a `.txt` file: it becomes `.txt.utenc`.
5. Double-click it: it opens in Notepad. Edit, save, close.
6. Pull the drive: `%APPDATA%\usbtether\open` is empty.
7. Uninstall from *Settings > Apps*.

## 6. Releasing

1. Bump `__version__` in `src/usbtether/__init__.py` and move the *Unreleased* entries in
   [CHANGELOG.md](../CHANGELOG.md) under the new version.
2. Run the checks (section 3), build (section 5), run the smoke test.
3. Commit, tag (`git tag v<version>`), push with tags.
4. Create a GitHub release and attach `usbtether-setup-<version>.exe`.

The executable is not code-signed, so Windows SmartScreen may warn on first run ("More info >
Run anyway"). Signing needs a code-signing certificate; add `SignTool=` to the `.iss` when you
have one.

## 7. Changing the icon

The icon is `src/usbtether/usbtether.ico`, drawn by
[packaging/make_icon.py](../packaging/make_icon.py) with the standard library only. Edit the
drawing there and run `python packaging\make_icon.py`.

## 8. Build troubleshooting

| Problem | Fix |
|---|---|
| `Inno Setup 6 not found` | install it, or set `$env:ISCC` to the full path of `ISCC.exe` |
| `running scripts is disabled` | use `powershell -ExecutionPolicy Bypass -File ...` as shown |
| The panel does not start from the built exe | the exe has no console, so errors are invisible; run `python -m usbtether app` from source to see them |
| Antivirus quarantines the exe | common with unsigned PyInstaller builds; sign it or add an exclusion for the build folder |
| `No module named tkinter` | install Python from python.org (some distributions ship without Tk) |
