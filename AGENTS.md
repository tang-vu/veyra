# Veyra contributor and AI maintainer contract

This is the canonical repository instruction file for human-assisted and autonomous contributors.
Read it completely before changing code, documentation, automation, packages, or project policy.
The retired bootstrap brief `goal.md` must not be recreated: current intent lives in `README.md`,
`ROADMAP.md`, `docs/`, architecture decisions, and the issue or task being implemented.

## Mission and standard

Veyra is an Apache-2.0, model-independent reversible execution kernel for AI agents. Optimize for
least authority, inspectability, honest recovery semantics, interoperability, and maintainability by
outside contributors. A change is not complete merely because it compiles; it must be safe to
review, documented at the correct public boundary, compatible or explicitly versioned, legally
distributable, and reproducibly verified.

Do not claim “production ready,” “sandboxed,” “tamper proof,” “reversible,” or “secure” beyond the
implemented trust boundary and evidence in the threat model. Prefer a small auditable behavior over
a broad implicit guarantee.

## Start every task

1. Read the user request, `git status`, and the nearest relevant documentation and tests. Preserve
   user-owned or unrelated changes; never reset or rewrite them for convenience.
2. Classify the change with the OSS change matrix below before editing. If several rows apply, meet
   all of them.
3. Inspect authoritative local types and behavior before relying on prose. For version-sensitive
   tools, dependencies, standards, or security advice, verify against current primary upstream
   documentation.
4. Make the smallest coherent change that closes the observable requirement and its failure path.
   Do not add speculative frameworks, telemetry, network services, dependencies, or governance.
5. Never expose credentials or private data in prompts, commands, diffs, fixtures, logs, screenshots,
   issues, or eval output.

## Build and verify

- Rust: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
  `cargo test --workspace --all-targets --all-features --locked`.
- Rust public docs: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`.
- TypeScript: `corepack pnpm install --frozen-lockfile`, `corepack pnpm format`,
  `corepack pnpm check`, `corepack pnpm lint`, `corepack pnpm test`, `corepack pnpm build`.
- OSS policy: `corepack pnpm oss:check`.
- Package archives after build: `corepack pnpm package:check`.
- Release contract: `corepack pnpm release:check` before proposing or pushing a version tag.
- Demo: `cargo run --locked -p veyra-cli -- demo --json` (add `--directory <path>` only when
  durable inspection is intended).
- Full local gate: `./scripts/verify.ps1` from PowerShell 5+ or `bash ./scripts/verify.sh`.

Use the pinned toolchains and lockfiles. On a host without the Windows MSVC linker, use the installed
GNU Rust toolchain for local evidence and state that limitation; supported CI still covers MSVC.

## Architecture boundaries

- `veyra-protocol` owns versioned wire/domain types and generated schema authority. It has no kernel
  dependencies.
- `veyra-policy` decides authority only. It never performs effects or trusts planner prose.
- `veyra-journal` owns append-only persistence, audit bindings, receipts, and recovery evidence.
- `veyra-executor` owns adapters and OS/network interaction. Adapters enforce their declared
  contracts but never grant authority.
- `veyra-core` is the trusted state machine and orchestration boundary.
- Server, CLI, SDK, and desktop request transitions through the same versioned local API. The bearer
  is an administrative root credential, not a cryptographic human identity.

Do not move a decision across these boundaries merely to avoid a dependency or test. When a new
boundary is justified, record it in an ADR.

## Security invariants

- Deny by default before adapter observation, then reevaluate authority against the exact preflighted
  effect. No effect executes without sufficient live, matching capability and required approval.
- Approval binds the canonical digest of the exact effect. Capability uses and optional approval
  nonce consumption are atomic with matching audit evidence per effect.
- Paths are clean relative paths traversed through no-follow capability handles and rechecked across
  preflight, staging, execution, verification, and rollback.
- A repeated idempotency key returns the authenticated known result or fails closed; it never implies
  that an unknown external effect is safe to repeat.
- Journal verification checks the event chain and every audit-bound durable state in both directions.
  Receipts are locally authenticated, not remote attestation or non-repudiation.
- Raw secrets use references, resolve only at the adapter boundary, and never serialize into normal
  plans, receipts, logs, client errors, or audit exports.
- Unsupported inputs, conditions, capability caveats, retry semantics, and protocol preconditions
  fail closed. V0.1 rejects non-empty preconditions rather than pretending to evaluate them.
- Shell interpolation is never implicit. Process execution is disabled unless exactly configured,
  high risk, byte/time bounded, and honestly irreversible.
- “Reversible” is reserved for verified restoration under documented preconditions. Compensation,
  partial compensation, cancellation, and manual recovery are distinct states.

Never weaken containment, canonicalization, audit binding, verification, approval, capability, or
idempotency behavior to make a test pass. Authorization, persistence, filesystem, HTTP, process, and
client-boundary changes require a negative/adversarial regression, not only a success test.

## OSS change matrix

| Change type                                       | Required companion work                                                                                                                                    |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public protocol or serialized type                | Versioning decision, Rust type tests, regenerated JSON Schemas, compatibility fixture, SDK type review, VEP/changelog update                               |
| Public Rust/TypeScript API or CLI                 | Public docs/examples, compatibility and SemVer assessment, typed errors, tests, changelog when observable                                                  |
| Authority, secrets, adapter trust, or containment | Threat-model review, adversarial test, eval scenario, residual-risk statement, security-policy scope check                                                 |
| Journal schema, durable state, or recovery        | Migration/legacy behavior, crash-boundary tests, audit binding, recovery classification, ADR when the storage contract changes                             |
| New adapter or effect operation                   | Exact inputs/resources, capability caveats, risk floor, preview, idempotency, timeout/limits, verification, rollback/compensation honesty, authoring docs  |
| Dependency or GitHub Action                       | Necessity and maintenance review, Apache-2.0 compatibility, advisory/license gate, lockfile, full-SHA Action pin with version comment, Dependabot coverage |
| Desktop or user-facing flow                       | Loading/empty/error/integrity/recovery states, keyboard/accessibility review, responsive behavior, real-API test, screenshots when visual behavior changes |
| Package or release                                | Manifest discovery metadata, README and license in archive, clean pack/dry run, checksums, provenance, changelog/release notes, no local artifacts         |
| Community or governance                           | GitHub-supported location/format, contributor clarity, Code of Conduct and governance consistency, no invented maintainers/funding/signing identities      |

## Dependencies and supply chain

- Keep dependencies restrained. Prefer the standard library or an existing dependency when it keeps
  the trusted boundary auditable.
- Before adding or upgrading a dependency, verify the official upstream source, release status,
  maintenance posture, transitive impact, license, advisories, and minimum runtime/toolchain.
- Commit lockfile changes with the manifest change. Never bypass `cargo deny`, `pnpm audit`, or the
  dependency review gate by hiding a dependency or weakening policy without documented review.
- Every external GitHub Action must use an immutable 40-character commit SHA and a nearby release
  comment. Workflow permissions are read-only by default and elevated only on the smallest job.
- Treat `github/codeql-action/init`, `autobuild`, `analyze`, and `upload-sarif` as one release unit:
  keep the same SHA/version across workflows and preserve their Dependabot group. Never accept a
  partial family update merely because one component's pull request is green.
- Keep `@types/node` on the minimum supported major recorded in `.node-version-min`, retain that
  compatibility job, and keep `.node-version` as the current default toolchain. A type-major update
  requires an intentional minimum-runtime compatibility change, not a type-only Dependabot merge.
- Security-boundary parsing and containment changes must update the relevant `fuzz/` target. Keep
  `cargo-fuzz`, its nightly toolchain, harness dependencies, input limits, and execution time bounded
  and pinned; never weaken a discovered invariant or commit corpora/crash artifacts to make fuzzing
  pass.
- Do not add generated binaries, vendored archives, package tarballs, local databases, browser traces,
  test results, or release artifacts to Git.
- Treat `.github/workflows/publish-packages.yml` as a credential-free rehearsal until real registry
  owners have bootstrap-published every package and configured the exact workflow as a trusted
  publisher. Do not add `id-token: write`, an authentication Action, or any registry write without
  explicit maintainer authorization and the prerequisites in
  `docs/maintainers/package-publishing.md`. Prefer short-lived OIDC credentials over repository
  tokens; publish multi-crate workspaces dependency-first and wait for registry visibility.

## Hosted OSS invariants

- Required status checks must report a conclusion on every matching pull request. Do not make a
  path-filtered workflow a global required check; either run its stable check on every pull request
  or keep it conditional and non-required.
- Preserve the host-side Actions allowlist and full-SHA enforcement. Adding a third-party Action
  also requires an authorized maintainer to narrow-update that allowlist; never broaden it to all
  verified or all marketplace Actions for convenience.
- GitHub Releases are immutable. Release automation must create a draft, attach and verify every
  asset, and publish only after the draft is complete. Never replace an asset or move a published
  release tag.
- Preserve binary-scoped SBOMs as a complete five-document contract: CLI and daemon on Linux and
  Windows plus the Windows desktop payload. Build them with the pinned auditable Cargo path, require
  the expected root PURL and exact executable subject digest, checksum and attest each document, and
  keep the separate repository SBOM. Extract the desktop subject from the completed NSIS installer in
  both release and consumer gates; never describe its Rust inventory as coverage of the NSIS
  bootstrapper or unreported native libraries.
- Preserve `.github/workflows/release-consumer.yml` as a public-artifact test, not a source-build
  substitute. It must resolve the annotated tag, require an immutable public Release, verify the
  manifest/checksums/exact signer and binary-SBOM subjects, then execute downloaded Linux and Windows
  archives with unauthenticated-denial and authenticated-health probes. Only immutable `v0.1.0` may
  retain the explicitly validated legacy evidence contract; never create another legacy exception or
  rewrite historical assets.
- Recover an unpublished tagged release only through the documented workflow on protected `main`.
  Require an existing annotated version tag resolving to every exact build checkout, rebuild and
  re-attest all outputs, preserve draft-first publication, and never delete, recreate, or move the
  tag to absorb workflow changes.
- A release tag, Cargo workspace, npm workspaces, Tauri bundle, dated changelog section, and curated
  `docs/releases/vX.Y.Z.md` notes must agree on one version. Preserve the tag-time release-contract
  check and disclose unsigned artifacts, residual security risk, package-registry status, checksum
  verification, provenance verification, and SBOM scope in those notes.
- Curated notes are rendered both as repository files and as GitHub Release metadata. Use absolute,
  tag-pinned HTTPS links for repository documents; never use a file-relative link whose base changes
  on the Release page. Preserve the release-contract assertions that enforce this dual-use format.
- Repository rulesets protect `main` and `v*` tags. Do not rename the required Linux, Windows,
  minimum-Node, dependency-review, CodeQL, or security-boundary fuzz check contexts, or weaken
  pull-request, linear-history, force-push, deletion, tag, or conversation-resolution rules without
  documenting the migration and verifying the resulting host state.
- Repository files cannot prove hosted settings. With authenticated read access, run
  `corepack pnpm oss:host-check` after changing workflows, release policy, or community/security
  settings. A host gate failure is evidence of drift, not a reason to weaken the local contract.
- Host mutations remain maintainer-only. When authority is absent, prepare exact documented changes
  and report the unverified host gap; never claim a setting was applied from source files alone.

## Documentation and community

- Write for users and outside contributors who lack private context. Examples must be runnable and
  security claims must link to actual behavior or the threat model.
- Use `SUPPORT.md` for safe support routing, `SECURITY.md` for private vulnerability reporting,
  `CONTRIBUTING.md` for contribution workflow, and `RELEASING.md` for maintainer releases.
- Changes to trust model, wire protocol, persistence format, adapter contract, or governance begin
  with a VEP/ADR or an issue that explicitly records the decision and compatibility impact.
- Keep `CHANGELOG.md` user-facing. Keep `PROGRESS.md` evidence-facing: exact commands, results,
  environment limitations, and remaining risks.
- Do not invent a `CODEOWNERS`, sponsor account, signing identity, support SLA, package owner, or
  security contact. These require real maintainers and host configuration.

## Definition of done

A task is complete only when all applicable items hold:

- observable success and failure behavior are implemented with proportionate tests;
- formatting, lint, type checks, public docs, tests, `oss:check`, and dependency gates pass;
- generated schemas/eval results are current when their sources or security invariants changed;
- public docs, examples, changelog, roadmap, threat model, and progress evidence are synchronized;
- the final diff contains no secrets, private data, debug output, placeholders, stale comments,
  unrelated edits, generated junk, or misleading guarantees;
- compatibility, migration, reversibility, and residual risks are stated explicitly;
- the working tree is inspected and the final report gives exact verification evidence.

Local commits are appropriate for a genuinely finished implementation when the task requests a
complete change. Never push, publish, deploy, create a remote release, change repository settings,
send external messages, or perform another maintainer-only action without explicit authorization.
