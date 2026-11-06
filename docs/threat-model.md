# Threat model

usbtether is a **convenience-grade, presence-bound credential for ordinary USB drives**. It
raises the cost of casual credential copying. It is not a hardware security module, and it is
not a substitute for a FIDO2/WebAuthn security key. Read this page before relying on it.

## What is protected

A session or capability that should exist only while a particular, previously enrolled USB
drive is plugged in to a host that trusts the registry.

## Trust assumptions

1. **The host is trusted.** The agent, verifier, registry and your application run on a
   machine you control. Malware on that machine defeats everything here.
2. **The registry is protected.** It is the trust anchor; whoever can write it can enroll
   tokens. It is not signed or encrypted.
3. **The operating system reports the drive's USB descriptor honestly.**

## What it stops

| Attack | Why it fails |
|---|---|
| Copy `.usbtether/` to another ordinary flash drive | The copy reports a different `(VID, PID, serial)`; the fingerprint does not match the registry. `device_mismatch`. |
| Re-use a recorded response (replay) | Challenges are single-use, expire in 30 s, and the signature covers the nonce. |
| Re-use a response for a different action or purpose | Purpose, token id and device claim are inside the signed payload. |
| Edit the on-drive files to point to another device | The device identity that counts lives in the host registry, not on the drive. |
| Forge `token.json` or swap the key | The private key must derive the stated public key, and the public key must be the registered one. |
| Use a drive with no real serial | Such drives cannot be enrolled, and their responses are refused. They are not silently downgraded. |
| Keep acting after unplugging | The presence monitor revokes the session; capabilities are re-checked against it and expire in seconds. |
| Spend one capability twice, or for another resource | Single use, HMAC-signed, scoped to one `(resource, action)`. |
| Lose the drive, or have it taken, and read the key | With `--passphrase` or `--remember` the key on the drive is encrypted. The passphrase is typed, or the secret stays on your computer (DPAPI on Windows) and never on the drive. |

## What it does **not** stop

| Attack | Why |
|---|---|
| **Drive with a spoofed descriptor** | The `(VID, PID, serial)` triple is public to any program that can read the drive. A device with re-programmable controller firmware, or a virtual device, can report the same values. A test (`test_spoofed_descriptor_is_accepted_known_limitation`) asserts that such a drive is *accepted*, so this limit is never forgotten. |
| **Imaging the whole drive** | A raw image copies the key too. The copy authenticates *only if* the destination also reports the original descriptor; see the previous row. |
| **A compromised host** | Malware can read the key, call the agent, patch the verifier or the registry. |
| **A lying remote agent** | If agent and verifier are on different machines, the device report is a *claim* of the agent's host. It is signed, but unattested. |
| **Stolen drive with an unencrypted key** | Possession of the drive is possession of the credential, for as long as the registry entry is active. Revoke it. |
| **Anyone logged in as you, or malware, with `--remember`** | The remembered secret unlocks silently for your Windows account. DPAPI separates accounts and machines, not processes. On Linux the secret file is protected by file permissions only. |
| **Tampering with the registry** | Not authenticated. |
| **Instant detection of unplugging** | Detection is polling (default 1 s), plus capability lifetime (8 s) as a second bound. |
| **Brute forcing a typed passphrase offline** | An attacker holding the drive can try passphrases offline; use a strong one. (A `--remember` secret is 256 random bits.) |

## Why the signature does not prove the drive is genuine

The agent builds the device report by asking the operating system and signs it with the key
read from the same drive. Both inputs are available to anyone who holds the drive. The
signature proves "someone with this key file made this claim", not "this hardware is the
original". The binding is only as strong as the cost of making another device present the
same descriptor, which for common flash drives ranges from impossible-for-casual-users to
inexpensive-for-motivated-attackers.

## Choosing something stronger

If an attacker who can spoof USB descriptors is in scope, use a device whose private key
cannot be exported: a FIDO2/WebAuthn security key, a smart card or an OpenPGP token. There
the clone problem does not exist, because the key never leaves the hardware. usbtether is for
the cases where that is not available or not worth its cost.

## Planned mitigations (not implemented)

* **Rolling secret** (idea from `pam_usb`'s one-time pads): replace a secret on drive and
  host after each success, so a copied drive diverges and the clone is *detected*. This
  detects rather than prevents, and cannot tell which copy is the original.
* Event-driven removal detection (Windows device notifications) instead of polling.
* Signed registry and signed revocation lists.
