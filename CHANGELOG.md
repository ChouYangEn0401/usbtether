# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break compatibility).

## [Unreleased]

### Added
- `usbtether vault lock|unlock|watch <folder>`: AES-256-GCM file vault keyed from the enrolled
  drive (`Agent.derive_key`). `watch` unlocks when the drive is plugged in and locks when it is
  removed. See the module docstring of `usbtether.vault` for the limits.
- `usbtether open <file.utenc>`: decrypt to a private working copy, open it with its usual
  program, encrypt every save back, and delete the copy when the drive is removed or the file
  is idle (`--idle-timeout`). Leftovers from a killed helper are synced back and removed on the
  next run (`usbtether.opener.sweep`).
- `usbtether register [--remove]` (Windows): per-user `.utenc` file association so
  double-clicking an encrypted file runs `usbtether open`.
- `encrypt_file` / `decrypt_file` take `dest_dir=` and `keep=`.
- Web demo tabs reorganised: 02 Vault Unlock Lab, **03 Encrypt / Decrypt** (two halves, drag
  and drop or native file dialog, auto/manual, delete-source toggle, in place or another
  folder), **04 Bound Folders** (folders kept encrypted, auto/manual encryption of new files,
  register the double-click association). The earlier "File Vault" auto-lock tab is gone; its
  engine is still `usbtether vault`.
- Web demo: the enroll page warns that `--force` makes files encrypted with the old key
  unrecoverable.
- Web demo: a **USB Authentication** tab to enroll and verify the drive from the page (CLI
  `enroll`/`verify` equivalents), shown before the Software Guard and Vault experiments.

### Fixed
- Windows probe took ~40 s and hit its 30 s timeout on machines with several internal disks.
  It now stops walking the PnP tree at the PCI root and skips SATA/NVMe disks (about 2 s),
  and the default timeout is 60 s.

## [0.2.0]

### Added
- `usbtether enroll --remember`: encrypt the private key with a random secret kept on the
  computer (Windows DPAPI; owner-only file elsewhere) so the drive unlocks without typing and is
  useless without that computer. The agent consults the host secret store automatically.
- `HostSecretStore` with `DpapiSecretStore`, `FileSecretStore` and `NullSecretStore`.
- `enroll(..., remember=True, secret_store=...)` and `Agent(..., secret_store=...)`.

### Changed
- `usbtether revoke` also removes the remembered secret; re-enrolling removes a stale one;
  a failed enrollment leaves no secret behind.
- The web demo explains how to fix a locked key instead of only asking for an environment
  variable.
- Confirmed on a real Windows machine and USB 3.0 drive (enroll and verify).

## [0.1.0]

First public version.

### Added
- Device model with `(VID, PID, serial)` identity, serial-quality classification and
  fingerprints; volume data kept as advisory fields.
- Windows USB discovery through PowerShell/CIM (covers UASP drives), with a pure,
  separately tested parser. Experimental Linux discovery through sysfs.
- On-drive Ed25519 token with optional passphrase protection; host-side registry as the
  trust anchor.
- `usbtether-auth-v1`: single-use, purpose-bound challenges; signatures over nonce, purpose,
  token id and the observed device; fingerprint comparison against the registry.
- Transactional enrollment with an authentication self-test and full rollback.
- Sessions, single-use HMAC-signed capabilities and a polling presence monitor.
- `usbtether` CLI: `devices`, `enroll`, `verify`, `list`, `revoke`.
- Web demo (Software Guard, Vault Unlock Lab) and an SDK quickstart.
- `requirements*.txt` files that delegate to `pyproject.toml`.
- Protocol specification, threat model, device-identity notes and architecture overview.
- Usage guide (English and Traditional Chinese): install, enroll, verify, management,
  troubleshooting.

### Known limitations
- A drive that reports the same USB descriptor as the enrolled one is accepted.
- Windows discovery has not yet been validated on a broad range of real drives.
- Removal detection is polling-based.
- The registry is neither signed nor encrypted.

[Unreleased]: https://github.com/ChouYangEn0401/usbtether/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ChouYangEn0401/usbtether/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ChouYangEn0401/usbtether/releases/tag/v0.1.0
