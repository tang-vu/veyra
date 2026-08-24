# Repository settings for maintainers

Files in the repository cannot enforce every GitHub-host setting. An authorized maintainer should
apply and periodically audit this checklist for the public `tang-vu/veyra` repository. Do not
mark an item complete in project evidence until it has been observed on GitHub.

The checked baseline below was observed on 2026-08-24. Run the read-only
`corepack pnpm oss:host-check` gate with authenticated maintainer access after relevant changes and
during periodic audits; source files alone are not evidence that hosted policy is active.

## Repository and community

- [x] Keep the repository public with the description “Reversible execution for AI agents.”
- [x] Add focused topics such as `ai-agents`, `capability-security`, `rust`, `audit-log`, and
      `reversible-execution`; do not use misleading “sandbox” or “blockchain” claims.
- [x] Enable Issues and private vulnerability reporting. Enable Discussions only when maintainers
      can moderate and answer them.
- [ ] Publish a durable private maintainer contact for conduct reports and security fallback; do not
      use a personal address that the owner cannot transfer or recover.
- [x] Keep `LICENSE`, `README.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`,
      `SUPPORT.md`, and `GOVERNANCE.md` visible in the community profile.

## Rulesets

Protect `main` with a repository ruleset:

- [x] require pull requests, resolved conversations, and at least one approval when another
      maintainer is available;
- [x] dismiss stale approvals after security-sensitive changes;
- [x] require the Linux full gate, Windows Rust gate, dependency review, and CodeQL checks;
- [x] block force pushes and branch deletion, require linear history, and include administrators
      except during a documented emergency;
- [x] restrict creation, update, and deletion of `v*` tags to release maintainers;
- [ ] require signed release tags once project signing identities and recovery procedures exist.

The repository currently has one direct maintainer. `Protect main` therefore requires zero approvals
until a second maintainer exists, but has no standing bypass actor; all other pull-request and check
requirements also apply to the administrator. `Protect release tags` allows only the repository
owner to bypass creation/update/deletion restrictions. Re-audit both rulesets when maintainership
changes.

An emergency bypass must be disclosed after the incident with the reason, affected commits, and
follow-up verification.

## Security and automation

- [x] Enable the dependency graph, Dependabot alerts and security updates, secret scanning, and push
      protection where GitHub makes them available.
- [x] Keep the default workflow token read-only. Grant write scopes only to the smallest individual
      job, as the release, provenance, and Scorecard workflows do.
- [x] Restrict Actions to GitHub-maintained, pnpm, and OpenSSF actions used by this repository; all
      action references must remain pinned to a full commit SHA.
- [x] Enforce immutable future GitHub Releases and keep release automation draft-first so every asset
      is attached before publication.
- [x] Review CodeQL and Scorecard SARIF findings in code scanning. Treat the Scorecard result as
      diagnostic evidence, not a badge-driven reason to weaken project policy.
- [ ] Review inactive collaborators, deploy keys, webhooks, environments, package owners, and
      recovery access at least quarterly.

The 2026-08-24 API audit found one direct administrator and no deploy keys, webhooks, environments,
Dependabot alerts, or secret-scanning alerts. The account does not expose the organization-only
non-provider-pattern and validity-check options; default secret scanning and push protection remain
enabled. The refreshed Scorecard SARIF retains one branch-protection diagnostic because approvals,
CODEOWNERS review, and last-push approval cannot be independently satisfied by the sole maintainer;
do not invent a reviewer to raise the score. Package ownership and recovery access still require a
manual quarterly review.

`CODEOWNERS`, sponsorship, package-registry publication, and signing identities require real named
owners or accounts. Do not invent them in source control merely to satisfy a checklist.

Authoritative references: GitHub's guides for
[community health files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file),
[repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets),
and [artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
plus the OpenSSF Scorecard action's
[workflow restrictions](https://github.com/ossf/scorecard-action#workflow-restrictions).
