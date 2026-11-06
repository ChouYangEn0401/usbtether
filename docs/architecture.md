# Architecture

```
src/usbtether/
  device.py       UsbDevice, Volume, DeviceReport, serial quality, fingerprint
  probe/
    base.py       DeviceProbe (abstract): the only code that talks to the OS
    windows.py    PowerShell/CIM probe + pure JSON parser
    linux.py      sysfs probe (experimental)
    memory.py     in-memory probe for tests and development
  token.py        on-drive credential: create / read / unlock
  registry.py     host-side trust anchor (JSON file)
  protocol.py     Challenge, Response, AuthResult, signing payload
  agent.py        reads the drive, signs challenges
  verifier.py     issues challenges, verifies responses
  enrollment.py   transactional enrollment with self-test and rollback
  authz.py        Session, Capability, Authorizer
  monitor.py      PresenceMonitor (revokes sessions on removal)
  cli.py          `usbtether` command
examples/
  sdk_quickstart.py   library usage
  web_demo/           FastAPI experiment harness
```

## Layering

```
        cli / your application / web demo
                       |
        Authorizer  (sessions, capabilities)  <--  PresenceMonitor
                       |
        Verifier  <-- Challenge / Response -->  Agent
            |                                      |
         Registry                              token.py
            |                                      |
        (host disk)                          DeviceProbe  --> OS --> USB drive
```

* **Authentication** (`Verifier`, `Agent`) answers "is this the enrolled token on the
  enrolled drive right now?".
* **Authorization** (`Authorizer`) decides what that allows, for how long.
* **Enrollment** creates the binding. It is the only code that writes to the drive.

Each layer only depends on the ones below it. The probe is the sole platform-specific piece:
porting to another OS means implementing `DeviceProbe.list_devices()`.

## Deployment shapes

**Single process** (CLI, desktop tool, the web demo): construct `Verifier`, `Agent` and
`Authorizer` together and use the `*_local` helpers.

**Split** (server verifies, desktop helper reads the USB): the helper runs the `Agent`; the
server runs `Verifier`/`Authorizer`. Move `Challenge.to_dict()` to the helper and
`Response.to_dict()` back. Note the trust consequence in `threat-model.md`: the server then
trusts the helper's device report. A transport between them is not part of this library.

## State

| State | Where | Lifetime |
|---|---|---|
| private key, token metadata | the USB drive | until the drive is wiped |
| public keys, fingerprints, revocations | `registry.json` on the host | persistent |
| pending challenges, sessions, capabilities, capability HMAC key | process memory | lost on restart (fail-safe) |

## Extension points

* **Another OS**: subclass `DeviceProbe`.
* **Another registry backend** (database, remote service): replace `Registry`; the verifier
  needs only `get`, and enrollment needs `add`, `remove`, `revoke`, `active_for_fingerprint`.
* **Another transport** between agent and verifier: serialise the dataclasses with `to_dict`.
