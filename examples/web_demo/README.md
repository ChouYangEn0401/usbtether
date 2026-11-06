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

Browsers cannot read USB serial numbers or drive contents, which is why the *server* reads the
drive. For a remote web application you would run the agent on the user's machine as a local
helper; see [docs/architecture.md](../../docs/architecture.md).
