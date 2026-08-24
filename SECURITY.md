# Security policy

## Supported versions

Veyra is pre-1.0. Security fixes are made on the latest `main` revision and the most recent tagged
release. Older snapshots are not supported unless a release note says otherwise.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [Report the vulnerability privately through
GitHub](https://github.com/tang-vu/veyra/security/advisories/new). If that feature is unavailable, use
a private contact method published by the repository owner and clearly mark the message
`SECURITY: Veyra`. If no private contact exists, open a detail-free public issue asking for a private
channel; do not disclose the vulnerability there. Do not include live credentials or third-party
data.

Please include:

- affected revision and platform;
- the trust boundary or invariant that fails;
- minimal reproduction steps or a test;
- realistic impact and required attacker access;
- whether you have observed exploitation.

Maintainers should acknowledge a complete report within seven days, coordinate remediation and
disclosure with the reporter, and publish credit when requested. Please allow a reasonable fix window
before public disclosure.

## Scope

High-value reports include capability or approval bypass, workspace escape, secret disclosure,
duplicate execution, receipt or journal forgery accepted as valid, unsafe recovery, API exposure
beyond loopback, and an adapter escaping its declared policy. Model jailbreaks without a trusted-core
invariant failure are not by themselves vulnerabilities; prompt injection that acquires tool
authority is.

The authoritative deployment assumptions and residual risks are in
[`docs/security/threat-model.md`](docs/security/threat-model.md). Never test against systems or data
you do not own or have permission to use.
