# Veyra AI contribution instructions

`/AGENTS.md` is the canonical and complete contributor contract. Read and follow it before editing
this repository; when these notes are shorter, `AGENTS.md` still applies.

- Preserve unrelated work and classify the change with the OSS change matrix before implementation.
- Keep protocol, policy, journal, executor, kernel, and client responsibilities in their documented
  boundaries.
- Deny authority by default and never weaken security or recovery invariants to satisfy a test.
- Add adversarial coverage for authorization, persistence, adapter, filesystem, and client-boundary
  changes.
- Update public docs, schemas, fixtures, SDK types, changelog, threat model, evals, and progress when
  the corresponding contract changes.
- Review every dependency for purpose, maintenance, license, advisories, and transitive impact. Pin
  GitHub Actions to full commit SHAs with version comments.
- Keep required checks unconditional on matching pull requests and preserve draft-first immutable
  releases, protected `main`/`v*` refs, and the host Actions allowlist.
- Run `corepack pnpm oss:check` and all relevant gates before claiming completion. When authenticated
  read access exists and hosted policy changed, also run `corepack pnpm oss:host-check`.
- Never include secrets, private data, databases, build output, browser traces, or package archives.
- Do not claim sandboxing, tamper-proof evidence, or production readiness beyond the threat model.
- Never push, publish, tag, deploy, modify remote settings, or invent maintainer identities without
  explicit authorization.
