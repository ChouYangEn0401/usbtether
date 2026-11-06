# Contributing

Thanks for helping. usbtether is a small security-adjacent library, so the bar is: **clear
claims, tested behaviour, no overstated security.**

## Setup

```bash
git clone <your fork>
cd usbtether
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Checks (CI runs the same)

```bash
ruff check .
ruff format --check .
mypy                  # strict, src/ only
pytest
```

All of it must pass on Linux and Windows. The unit tests need no USB hardware: they use
`InMemoryProbe`, recorded PowerShell output and a fake sysfs tree.

## Guidelines

* **Do not write your own cryptography.** Use `cryptography`. New signed or hashed byte
  sequences go through `canonical_json` and need a new version identifier (see
  `docs/protocol.md`, section 9).
* **Do not weaken a documented guarantee silently.** If behaviour changes, update
  `docs/threat-model.md` and the tests in the same change. A limitation that is true should
  be asserted by a test (see `test_spoofed_descriptor_is_accepted_known_limitation`).
* **Fail closed.** When an identity cannot be established, refuse; never downgrade.
* **The probe is read-only.** Probes must never write to a device or the system.
* Keep the platform-specific code in `usbtether/probe/`.
* Add tests with every change. Prefer testing through the public protocol
  (`Verifier`/`Agent`/`Authorizer`) over internals.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(scope): ...`,
`fix(scope): ...`, `docs: ...`, `test: ...`, `chore: ...`. One logical change per commit.
Describe *why* in the body when it is not obvious. Update `CHANGELOG.md` under *Unreleased*.

## Reporting drive behaviour

The most valuable contribution right now is data about real drives. Run

```bash
usbtether devices --json --redact
```

and open an issue using the **Drive report** template. Serial numbers are redacted by
`--redact`; please check the output before posting.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
