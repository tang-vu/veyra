# Repository settings for maintainers

Files in the repository cannot enforce every GitHub-host setting. An authorized maintainer should
apply and periodically audit this checklist for the public `tang-vu/veyra` repository. Do not
mark an item complete in project evidence until it has been observed on GitHub.

## Repository and community

- [ ] Keep the repository public with the description “Reversible execution for AI agents.”
- [ ] Add focused topics such as `ai-agents`, `capability-security`, `rust`, `audit-log`, and
      `reversible-execution`; do not use misleading “sandbox” or “blockchain” claims.
- [ ] Enable Issues and private vulnerability reporting. Enable Discussions only when maintainers
      can moderate and answer them.
- [ ] Publish a durable private maintainer contact for conduct reports and security fallback; do not
      use a personal address that the owner cannot transfer or recover.
- [ ] Keep `LICENSE`, `README.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`,
      `SUPPORT.md`, and `GOVERNANCE.md` visible in the community profile.

## Rulesets

Protect `main` with a repository ruleset:

- [ ] require pull requests, resolved conversations, and at least one approval when another
      maintainer is available;
- [ ] dismiss stale approvals after security-sensitive changes;
- [ ] require the Linux full gate, Windows Rust gate, dependency review, and CodeQL checks;
- [ ] block force pushes and branch deletion, require linear history, and include administrators
      except during a documented emergency;
- [ ] restrict creation, update, and deletion of `v*` tags to release maintainers;
- [ ] require signed release tags once project signing identities and recovery procedures exist.

An emergency bypass must be disclosed after the incident with the reason, affected commits, and
follow-up verification.

## Security and automation

- [ ] Enable the dependency graph, Dependabot alerts and security updates, secret scanning, and push
      protection where GitHub makes them available.
- [ ] Keep the default workflow token read-only. Grant write scopes only to the smallest individual
      job, as the release, provenance, and Scorecard workflows do.
- [ ] Restrict Actions to GitHub-maintained, pnpm, and OpenSSF actions used by this repository; all
      action references must remain pinned to a full commit SHA.
- [ ] Review CodeQL and Scorecard SARIF findings in code scanning. Treat the Scorecard result as
      diagnostic evidence, not a badge-driven reason to weaken project policy.
- [ ] Review inactive collaborators, deploy keys, webhooks, environments, package owners, and
      recovery access at least quarterly.

`CODEOWNERS`, sponsorship, package-registry publication, and signing identities require real named
owners or accounts. Do not invent them in source control merely to satisfy a checklist.

Authoritative references: GitHub's guides for
[community health files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file),
[repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets),
and [artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
plus the OpenSSF Scorecard action's
[workflow restrictions](https://github.com/ossf/scorecard-action#workflow-restrictions).
