## Summary

Describe the observable change and why it belongs in Veyra.

## Trust and compatibility impact

- Authority or resource scope:
- Recovery or reversibility:
- Wire/API/persistence compatibility:
- New dependencies or privileged code:

Write `none` only after checking the relevant boundary. Link a VEP or ADR for trust-model,
protocol, persistence-format, governance, or adapter-contract changes.

## Verification

List exact commands and results. Include failure-path or adversarial coverage for security-sensitive
changes.

## Contributor checklist

- [ ] The change is focused and contains no credentials, private data, build output, or unrelated edits.
- [ ] Public behavior, compatibility impact, and residual risks are documented honestly.
- [ ] Relevant tests pass; authorization/filesystem changes include adversarial coverage.
- [ ] Protocol types, generated schemas, fixtures, SDK types, and VEPs remain synchronized where applicable.
- [ ] `CHANGELOG.md`, user docs, and `PROGRESS.md` are updated when behavior or evidence changes.
- [ ] New dependencies have a justified purpose, compatible license, maintained upstream, and locked version.
- [ ] GitHub Actions use full commit SHAs with a version comment.
- [ ] `corepack pnpm oss:check` and the relevant verification gate pass.
- [ ] Package or release changes pass `corepack pnpm package:check` after a build.
