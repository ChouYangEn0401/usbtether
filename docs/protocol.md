# Protocol specification: `usbtether-auth-v1`

This document specifies the on-drive token format, the host registry, the authentication
exchange and the authorization objects. The reference implementation is this repository;
where text and code disagree, the code and its tests are authoritative and the text is a bug.

Words such as MUST and SHOULD are used as in RFC 2119.

## 1. Roles

| Role | Holds | Does |
|---|---|---|
| **Token** (the USB drive) | Ed25519 private key | Nothing by itself. A passive file store. |
| **Agent** | access to the plugged-in drive | Reads the token, observes the drive's identity, signs challenges. |
| **Verifier** | the registry, challenge state | Issues challenges, verifies responses, compares drive identity. |
| **Authorizer** | verifier, capability signing key | Turns verified responses into sessions and capabilities. |

In the reference implementation the agent and verifier may run in one process
(`Verifier.authenticate`) or be split. Everything exchanged between them is JSON
serialisable (`to_dict` / `from_dict`).

An ordinary USB drive cannot compute signatures. The signing key is *read from* the drive
and used *by the agent*. The protocol therefore proves possession of a key **file** plus the
agent's claim about which drive it came from. See `threat-model.md`.

## 2. Encodings

* **Canonical JSON**: UTF-8-safe ASCII, keys sorted, separators `,` and `:`, no whitespace,
  no NaN/Infinity. Signed and hashed payloads MUST NOT contain floating-point numbers.
* **base64url** without padding for nonces and signatures; standard base64 for public keys
  stored in files.
* **Time** inside challenges is Unix seconds (float). It is never part of a signed payload.

## 3. Drive identity

The identity of a drive is the triple from the USB device descriptor:

```
(vendor_id, product_id, serial)        vendor_id, product_id: 4 lowercase hex digits
                                       serial: trimmed and upper-cased
fingerprint = SHA-256( canonical_json({
    "scheme": "usbtether-device-v1",
    "vid": vendor_id, "pid": product_id, "serial": serial }) )     // hex
```

A drive is **bindable** only if its serial is classified `good` (see `device-identity.md`).
Volume serial, file system, capacity and product name are *advisory*: they are recorded at
enrollment and compared on every verification, but a difference only yields a warning
(`volume_serial_changed`, `filesystem_changed`, `capacity_changed`, `product_changed`).

## 4. On-drive token

Directory `<mount>/.usbtether/`:

| File | Content |
|---|---|
| `private_key.pem` | Ed25519 private key, PKCS#8 PEM. Optionally encrypted (`BestAvailableEncryption`) with a typed passphrase, or with a random secret from the host secret store (4.1). |
| `token.json` | Public description, written **last** (commit marker). |

```json
{
  "format": "usbtether-token",
  "version": 1,
  "token_id": "0b6a0c4e-6c67-4b0c-9a58-2a7d1f4a8d11",
  "public_key": "<base64 of the 32 raw public-key bytes>",
  "key_file": "private_key.pem",
  "key_encrypted": false,
  "created_at": "2026-11-06T09:00:00Z"
}
```

Readers MUST reject a token whose `format`/`version` is unknown, whose `token_id` is not a
UUID, whose public key is not 32 bytes, or whose private key does not derive the stated
public key.

### 4.1 Host secret store (non-normative)

Enrollment with `remember` encrypts the key with 32 random bytes (64 hex characters) that are
stored **only on the host**, one file per token id, `secrets/<token_id>.bin` next to the
registry. On Windows the file content is sealed with DPAPI (`CryptProtectData`, current user,
no UI); elsewhere it is a file with owner-only permissions. The agent consults the store
first and falls back to a supplied passphrase. The store never changes what is signed or
verified; it only decides how the private key file is unlocked.

## 5. Host registry

A JSON file (default `%APPDATA%\usbtether\registry.json`, `~/.local/share/usbtether/` on
Linux, overridable with `USBTETHER_HOME`). It is the **trust anchor**.

```json
{
  "version": 1,
  "entries": {
    "<token_id>": {
      "token_id": "<token_id>",
      "public_key": "<base64>",
      "fingerprint": "<64 hex>",
      "device": { "vendor_id": "0781", "product_id": "5567", "serial": "...",
                  "product": "...", "volume_serial": "...", "filesystem": "exFAT",
                  "capacity": 32000000000 },
      "enrolled_at": "2026-11-06T09:00:00Z",
      "label": "desk key",
      "status": "active",
      "revoked_at": null
    }
  }
}
```

The file is written atomically (temporary file, `fsync`, rename). It is not signed or
encrypted: whoever can write it can enroll tokens. Protect it like a credential store.

## 6. Enrollment

1. Locate the drive at the given mount point. Refuse if it is not bindable.
2. Refuse if the drive already carries a token, or the registry holds an active entry for
   the same fingerprint, unless overwrite was requested.
3. Generate an Ed25519 key pair; write `private_key.pem`, then `token.json`.
4. Add the registry entry (public key, fingerprint, advisory data).
5. Run a real authentication exchange (purpose `enrollment-selftest`) as a self-test.
6. If **any** step fails, delete the token files and the registry entry and re-raise.
7. On success with overwrite, revoke every superseded token.

The private key never leaves the drive during enrollment.

## 7. Authentication exchange

```
Verifier                                         Agent
  |  Challenge{nonce, purpose, expires_at} ----->  |
  |                                                 |  read token.json, observe drive
  |                                                 |  sig = Ed25519(sk, signing_payload)
  |  <-------- Response{nonce, token_id, device, sig}
  |  verify
```

### 7.1 Challenge

`nonce`: 32 random bytes, base64url. `purpose`: a string chosen by the verifier that scopes
the challenge (`"session"`, `"vault-unlock:<id>"`, ...). `expires_at`: default 30 s ahead.
A challenge is **single use**: the verifier forgets it on the first response, whether or not
that response is valid. The verifier bounds its pending-challenge table (default 1024).

### 7.2 Signing payload

```
signing_payload = "usbtether-auth-v1" 0x0A canonical_json({
    "protocol": "usbtether-auth-v1",
    "nonce":    <nonce>,
    "purpose":  <purpose>,
    "token_id": <token_id>,
    "device":   { vendor_id, product_id, serial, product, volume_serial,
                  filesystem, capacity }          // the agent's DeviceReport, all fields
})
signature = Ed25519_sign(private_key, signing_payload)        // base64url
```

Binding nonce, purpose, token and the device claim into one signature means a signature
cannot be reused for another purpose, challenge, token, or altered device description.

### 7.3 Verification

The verifier MUST evaluate in this order and stop at the first failure:

| # | Check | Failure reason |
|---|---|---|
| 1 | `nonce` is a pending challenge (consumed now) | `unknown_challenge` |
| 2 | not past `expires_at` | `challenge_expired` |
| 3 | challenge purpose equals the expected purpose, if one is required | `purpose_mismatch` |
| 4 | `token_id` is in the registry | `unknown_token` |
| 5 | entry status is `active` | `token_revoked` |
| 6 | reported serial classifies as `good` | `device_unsupported` |
| 7 | Ed25519 signature verifies under the registered public key | `bad_signature` |
| 8 | fingerprint of the reported device equals the registered one (constant-time) | `device_mismatch` |

Success returns the token id, the fingerprint and any advisory warnings. The agent also
refuses to sign an already expired challenge, and refuses drives that are not bindable.

## 8. Sessions and capabilities

* **Session**: opened by one successful exchange with purpose `session`. Records the token id
  and drive fingerprint. Default lifetime 3600 s. Carries no authority.
* **Capability**: issued only after a *fresh* exchange with purpose
  `"capability:" + canonical_json([resource, action])` whose token id equals the session's.

```json
{ "capability_id": "...", "session_id": "...", "resource": "db", "action": "write",
  "expires_at_ms": 1762419008500, "max_uses": 1, "signature": "<hex HMAC-SHA256>" }
```

`signature = HMAC-SHA256(authorizer_key, canonical_json(all fields except signature))`. Expiry is an
integer number of milliseconds so that the signed bytes contain no floats. The key is random per
`Authorizer` instance and never leaves memory.

`consume(capability, resource, action)` fails with one of: `unknown_capability`,
`bad_signature`, `scope_mismatch`, `capability_expired`, `capability_used`,
`session_inactive` / `unknown_session`. Defaults: capability lifetime 8 s, one use.

A session is revoked (`revoked_reason`) by `revoke_session` or by the `PresenceMonitor`
(`device_removed`, `probe_failed`). Revocation is permanent: re-plugging the drive does not
revive it, a new authentication is required. All capabilities of a revoked session fail.

## 9. Versioning

The protocol identifier, token `version`, registry `version` and the fingerprint `scheme`
are independent and each carries its own version string. A change that alters any signed or
hashed byte sequence MUST introduce a new identifier rather than modify an existing one.
