# Governance

Veyra is an open-source, maintainer-led project. The maintainers are the contributors with commit
access identified by the repository host. This document describes the operating model; it does not
create a legal entity.

## Decisions

Routine changes are decided through review by an unaffected maintainer. Trust-model, wire-protocol,
persistence-format, or governance changes need a written VEP/ADR, a public review period appropriate
to impact, and agreement from at least two maintainers when the project has that many. Security fixes
may be developed privately and documented after coordinated disclosure.

Decisions prefer rough consensus supported by tests and explicit tradeoffs. When consensus is not
possible, maintainers may vote; a simple majority decides routine matters and two-thirds decides
governance or compatibility changes. A maintainer with a material conflict must disclose it and
recuse themselves.

## Roles

Contributors submit issues, code, documentation, tests, or reviews. Reviewers are trusted recurring
contributors who can approve in their area. Maintainers merge changes, manage releases and security
responses, and protect architectural and security invariants. Existing maintainers may grant or
remove roles based on sustained contribution, judgment, availability, and conduct—not employment or
company affiliation alone.

## Releases

A maintainer prepares a changelog, verifies schemas and eval results, runs the full gate, and records
known limitations. Another maintainer reviews security-sensitive releases when available. Tags follow
semantic versioning; until 1.0, minor versions may contain documented wire changes. Release workflows
produce checksummed artifacts and GitHub build-provenance attestations. Binaries and installers
remain unsigned at the platform level unless authorized maintainers separately configure code
signing; registry publication remains an explicit maintainer action.

## Project assets

Repository access, package namespaces, domains, signing keys, and vulnerability reports are held for
the project and should have at least two maintainers able to recover them when feasible. No one may
use project access to bypass review or conceal a conflict.

Governance amendments follow the same process as other governance changes and are recorded in the
repository history.
