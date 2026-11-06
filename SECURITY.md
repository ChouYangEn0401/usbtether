# Security policy

## Scope

usbtether is **alpha software** with a deliberately limited security level: see
[docs/threat-model.md](docs/threat-model.md). Behaviour listed there under *What it does not
stop* (for example, a drive that spoofs the original USB descriptor, or a compromised host) is
a documented limitation, not a vulnerability.

In scope: flaws that break a documented guarantee, such as

* authentication succeeding with a copied token on a drive reporting a different identity;
* replay of a challenge or response, or reuse of a capability;
* bypassing revocation, expiry, purpose or scope checks;
* the private key or passphrase being exposed, logged or written somewhere unintended;
* the enrollment rollback leaving a valid token behind after a failure;
* parsing flaws in the token, registry or probe output that can be triggered by crafted
  drive contents.

## Reporting

Please use GitHub's **private vulnerability reporting** (repository *Security* tab, *Report a
vulnerability*), or go directly to <https://github.com/ChouYangEn0401/usbtether/security/advisories/new>.
Do not open a public issue for security problems.

Include the version, platform, a description, and, if possible, a failing test or steps to
reproduce. Remove or redact real serial numbers.

Expect an acknowledgement within a reasonable time. This is a volunteer project and there is
no bug bounty.

## Supported versions

Only the latest 0.1.x release receives fixes.
