# Support

Veyra is a pre-1.0, community-maintained project. Support is best effort and carries no response-time
or compatibility guarantee beyond the policy documented for the latest release.

## Before asking

Check the [README](README.md), [documentation index](docs/README.md),
[safe workspace example](examples/safe-workspace/README.md), current
[roadmap](ROADMAP.md), and existing issues. Reproduce against the latest tagged release or current
`main` when practical.

Use the repository forms for:

- a reproducible defect: **Bug report**;
- a focused usage question: **Usage question**;
- a new capability or behavior: **Feature request**.

Include the Veyra version or commit, operating system and architecture, relevant Rust/Node versions,
the smallest reproduction, expected and actual behavior, and concise redacted evidence. Maintainers
may close reports that cannot be reproduced or that omit essential context after a follow-up.

## Keep reports safe

Never attach API tokens, receipt keys, environment files, provider credentials, private SQLite
journals, production workspace contents, or third-party data. Use a new temporary workspace and
replace identifiers or paths when they are not necessary to reproduce the issue.

Suspected vulnerabilities must follow [SECURITY.md](SECURITY.md) and use GitHub private
vulnerability reporting. Do not open a public issue, pull request, or discussion containing an
unfixed security report.
