# Progress

## 2026-08-23 — baseline

- Repository contained only the untracked specification `goal.md`; no implementation or history was present.
- Environment: Rust/Cargo 1.96.0, Node 24.14.1, pnpm 11.20.0, Windows 10; global `cargo-tauri` is not installed.
- Reviewed current official Tauri 2 setup, Axum 0.8 serving, SQLite crate guidance, pnpm workspace guidance, and the OpenAI Responses structured-output contract.
- Selected a Rust 2024 workspace pinned to Rust 1.96 and a pnpm workspace. Tauri is kept as a project-local dependency.
- Active bottleneck: compile and test the authoritative protocol/state-machine layer, then build policy + journal + filesystem as the first real vertical slice.

Commands run:

```text
rustc --version
cargo --version
node --version
pnpm --version
cargo search <dependency>
cargo info schemars reqwest rusqlite rand sha2 hmac
```

Known limitations: no runnable product exists yet; all goal requirements remain open until their milestone verification is recorded.

## 2026-08-23 - trusted vertical slice

- Implemented the complete versioned protocol, canonical RFC 8785 digests, secret-safe inputs, and generated JSON Schemas.
- Implemented and property-tested the explicit transaction state graph and deny-by-default capability/approval policy.
- Implemented durable SQLite snapshots, a redacted hash-chained journal, authenticated receipts, single-use approval nonces, idempotency reservations, and conservative crash recovery classification.
- Implemented capability-confined filesystem read/create/patch/move/delete with structured previews, staging, TOCTOU checks, verification, and non-clobbering rollback.
- Implemented bounded HTTP and disabled-by-default argv-only process adapters, the contributor adapter trait, deterministic planner, and OpenAI Responses-compatible planner boundary.
- Replaced the daemon and CLI placeholders with an authenticated `/v1` loopback API and useful commands. `veyra demo --json` now performs a real seed, preview, exact approval, execution, receipt inspection, postcondition verification, rollback, and audit-chain verification without credentials.

Commands run successfully on this Windows host (GNU Rust is used because Visual Studio `link.exe` is absent):

```text
cargo +stable-x86_64-pc-windows-gnu test -p veyra-core --lib
cargo +stable-x86_64-pc-windows-gnu test -p veyra-journal --lib
cargo +stable-x86_64-pc-windows-gnu test -p veyra-server --lib
cargo +stable-x86_64-pc-windows-gnu test -p veyra-cli
cargo +stable-x86_64-pc-windows-gnu clippy -p veyra-policy -p veyra-journal -p veyra-executor -p veyra-core --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu clippy -p veyra-server -p veyra-cli --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu run -p veyra-protocol --example generate-schema -- packages/protocol-schema/schema
node packages/protocol-schema/scripts/verify-generated.mjs
node --test packages/protocol-schema/tests/schema.test.mjs
```

Known limitations and next bottleneck: crash-boundary injection and cross-process concurrency need broader integration coverage; HTTP compensation remains explicitly separate authority; the TypeScript SDK, real Tauri UI, docs, eval suite, and release gates are next. Native Tauri compilation on this host requires the documented MSVC C++ Build Tools installation.

## 2026-08-23 - SDK and desktop control plane

- Added a strict ESM TypeScript SDK covering every `/v1` endpoint, with enforced loopback URLs, bearer authentication, encoded identifiers, typed responses, and safe API errors.
- Built the React/Tauri desktop control plane against that SDK and the same real daemon used by the CLI. It includes intent entry, transaction navigation, effect/diff inspection, exact-scope risk approval, causal timeline, receipt and verification evidence, rollback, audit search, manual-recovery/error/loading/empty states, responsive layouts, keyboard focus, and dark/light themes.
- The Tauri host now creates a durable local kernel, binds an ephemeral loopback listener, and passes connection material to the trusted webview command boundary. Standard application icons were generated from the source `icon.svg` mark.
- Replaced the custom-adapter placeholder with a complete, tested out-of-tree reversible counter example that refuses clobbering rollback.
- Ran a real Playwright flow using Microsoft Edge and a live Rust daemon. It created, preflighted, approved, executed, verified, inspected, and rolled back a transaction. Screenshots were inspected at 1440x900 and 760x900; a small approval-copy spacing issue was found and fixed.

Commands run successfully:

```text
pnpm install
pnpm check
pnpm test
pnpm build
VEYRA_E2E_TOKEN_FILE=<absolute-token-path> pnpm --filter @veyra/desktop test:e2e
cargo +stable-x86_64-pc-windows-gnu check -p veyra-desktop
cargo +stable-x86_64-pc-windows-gnu test -p veyra-custom-adapter-example
cargo +stable-x86_64-pc-windows-gnu clippy -p veyra-custom-adapter-example --all-targets -- -D warnings
```

Known limitations and next bottleneck: the visual E2E requires a running daemon and installed Edge/Chrome; native Windows checks use the installed GNU toolchain because MSVC Build Tools are absent. Security/crash eval expansion, documentation, CI/release assets, and the final skeptical review remain.

## 2026-08-23 - release-quality hardening and final verification

- Made every restart phase conservative: pre-effect drafts/preflights cancel or fail safely, while
  ambiguous staging/execution/verification/compensation phases enter manual recovery. Added bounded,
  depth-checked adapter evidence and complete postcondition coverage so malformed adapters cannot
  manufacture a commit. Causal effect parents must point backward, idempotency keys are bounded and
  adapter-unique within a plan, and rollback now recovers every known stage while honestly reporting
  missing crash-boundary evidence as partial compensation.
- Hardened filesystem mutation around capability-directory handles, final-component no-follow opens,
  transaction-bound staged details, exact captured/prepared-byte checks, collision-safe capture,
  atomic no-replace hard-link commits, and non-clobbering rollback. Added Windows reserved-name,
  alternate-data-stream, separator, trailing
  dot/space, and case-insensitive `.veyra` rejection.
- Hardened HTTP against redirects, automatic retries, DNS rebinding, private/special/mapped addresses,
  oversized resolution sets, duplicate or oversized request headers, sensitive query parameters,
  reflected credentials, and unbounded response bodies or headers. Process execution remains
  disabled by default, direct-argv only, environment-cleared,
  executable-digest checked, and byte/time bounded.
- Added immutable-object digest checks, snapshot/index consistency checks, and a transactionally
  updated local audit count/head anchor. The verifier now detects payload mutation, missing links,
  reordered events, and deletion of the current tail (but not a privileged attacker rewriting the
  entire database and anchor).
- Bounded planner, CLI, API, SDK, and adapter inputs/outputs; disabled provider redirects and retries;
  tightened loopback URL and token validation; added secret-safe truncation and non-amplifying
  redaction. Documented that the local bearer is administrative root and does not cryptographically
  identify separate humans in V0.1.
- Added CI on Linux and Windows MSVC, dependency auditing, Dependabot, tag-driven unsigned release
  artifacts with checksums, OSS governance/security documents, the custom-adapter contract, and a
  39-scenario machine-readable adversarial suite.
- Re-ran the real Microsoft Edge flow against an optimized daemon. It reviewed an exact diff at
  1440x900 and 760x900, approved, executed, displayed authenticated receipt/postcondition evidence,
  and rolled back. Visual inspection found no clipping or hierarchy defects. A bootstrap connection
  error discovered during the run is now surfaced and regression-tested.

Final gates passed on this Windows host:

```text
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace --all-targets --all-features --locked
cargo +stable-x86_64-pc-windows-gnu run --locked -p veyra-protocol --example generate-schema -- packages/protocol-schema/schema
node packages/protocol-schema/scripts/verify-generated.mjs
git diff --exit-code -- packages/protocol-schema/schema
cargo deny check advisories bans licenses sources --hide-inclusion-graph
corepack pnpm install --frozen-lockfile
corepack pnpm format
corepack pnpm check
corepack pnpm lint
corepack pnpm test
corepack pnpm build
corepack pnpm audit --prod --audit-level high
corepack pnpm eval
cargo +stable-x86_64-pc-windows-gnu run --locked -p veyra-cli -- demo --json
cargo +stable-x86_64-pc-windows-gnu build --release -p veyra-cli -p veyra-server --locked
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; corepack pnpm desktop:build
VEYRA_E2E_TOKEN_FILE=<absolute-token-path> corepack pnpm --filter @veyra/desktop test:e2e
```

The eval result is 38 passed, 1 environment-limited, and 0 failed. EV-008's real symlink fixture is
Unix-only because this Windows account cannot create symlinks without Developer Mode or elevation;
lexical traversal and capability-containment tests still pass here, and CI runs the fixture on Linux.
The deterministic demo committed, authenticated 1 receipt, passed 1 verification, checked 22 audit
events, rolled back, and removed the created file.

Local unsigned release artifacts were built successfully: `veyra.exe`, `veyra-server.exe`,
`veyra-desktop.exe`, and `Veyra_0.1.0_x64-setup.exe`. This host lacks MSVC `link.exe`, so the local
bundle used the installed GNU Rust toolchain; the release workflow defines the supported Windows
MSVC build. Remaining limitations are explicit in the threat model and roadmap: one local OS-account
trust boundary, administrative bearer identity, in-process adapter trust, conservative manual
recovery for unknowable external outcomes, retained staging artifacts, hard-link-dependent
no-replace filesystem mutation, and no protection from a privileged attacker rewriting both the
journal and its local anchor.

The final hardened tree increased the focused kernel/executor coverage to 26 and 22 tests,
respectively, added compatibility fixtures, and passed the live Edge release-daemon flow in 19.4s.
Final local artifact SHA-256 values are:

```text
0783cc74b637aebdfb70929bb0b920a7be518ae29c3322601a0a5a1bc35f2361  target/release/veyra.exe
de702be10b4fafeb741f89f953003a59450fe83715a7b7b2efc848df3a1825ac  target/release/veyra-server.exe
c2595f3ba15fe59444b835bab5103b2e9870436af090d57f77b080c97af3dbba  target/release/veyra-desktop.exe
14c78673953130728232bbe3d5717ab437821183eb5fb8bec5f70d24bbdd3916  target/release/bundle/nsis/Veyra_0.1.0_x64-setup.exe
```

## 2026-08-24 - deep feature audit and durable-state hardening

- Moved authorization ahead of adapter observation, then reevaluated the exact preflighted effect.
  Capability issuance now has semantic/size/time/use bounds, transaction and principal binding, and
  virtual plan-wide use reservation. Each effect consumes capability uses, its optional approval
  nonce, and matching audit evidence atomically; approval grant retry is idempotent for the same
  approver and conflicting for a different one.
- Bound transaction snapshots, immutable objects, capability content and mutable facts, approval
  replay rows, stages, and idempotency rows to reserved audit events. Verification checks both
  materialized-state-to-audit and audit-to-materialized-state directions, validates semantic event
  shape, detects deletion and malformed stored JSON/timestamps, and holds the journal lock for the
  complete verification pass. Receipt completion must authenticate the exact reserved effect.
- Added hard-limited keyset pages for transactions, audit history/export, and recovery. Startup
  recovery scans every bounded page. Transaction bundles now read transaction, protocol objects,
  approvals, execution evidence, and events through one SQLite read snapshot; a concurrent-update
  regression proves revisions cannot be mixed.
- Tightened every bundled adapter contract: exact inputs, honest risk floors, supported
  postconditions only, no unimplemented preconditions, no credential-shaped public data, canonical
  SHA-256/resource text, and fail-closed third-party capability caveats. Filesystem diffs preserve
  UTF-8 within their exact byte budget. Process approval binds executable bytes; output overflow or
  timeout actively aborts readers and terminates/reaps the child.
- Added bounded paged API, CLI, and TypeScript SDK surfaces; safe same-origin CLI URL construction;
  typed path IDs; bearer challenges; no-store/nosniff responses; token-redacted, control-safe client
  errors; and Unicode-aware truncation. The desktop progressively loads older records, prevents a
  stale bundle response from replacing the current selection, and renders failed journal
  verification as a persistent integrity alert.
- Expanded the adversarial catalog from 39 to 64 scenarios. A focused verbose desktop eval gate
  makes the UI race probe observable instead of inferring it from an aggregate test count.

Final gates passed on this Windows host using the GNU Rust toolchain:

```text
$env:VEYRA_RUST_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; .\scripts\verify.ps1
cargo +stable-x86_64-pc-windows-gnu build --release -p veyra-cli -p veyra-server --locked
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; corepack pnpm desktop:build
VEYRA_E2E_TOKEN_FILE=<absolute-token-path> corepack pnpm --filter @veyra/desktop test:e2e
```

The complete workspace run passed 109 Rust tests and 15 JavaScript/TypeScript/UI tests, generated
and checked all 16 protocol schemas, built production web assets, and passed Rust and production
JavaScript dependency policy checks. The eval result is 63 passed, 1 environment-limited, and 0
failed; EV-008 remains the documented unprivileged-Windows symlink-fixture limitation and runs on
Linux CI. The deterministic demo committed one effect, authenticated one receipt, passed one
verification, checked 39 audit events, rolled back, and removed the workspace file.

The live Microsoft Edge release-daemon flow passed in 23.4 seconds at 1440x900 and 760x900. It
created, preflighted, approved, executed, verified, inspected, and rolled back a real transaction.
The approval, narrow, and committed screenshots were inspected directly; no horizontal overflow,
clipped control, hidden primary action, or evidence-hierarchy defect was found.

Local unsigned release artifact SHA-256 values are:

```text
c1dec48f1789165755151bf5341ebf49d9b41aadb7a36bcd2740656012f579c9  target/release/veyra.exe
ae891ea858daf9e11670b8d2a38baa59bef7f3d9906ab5e200b8d9b163435fe0  target/release/veyra-server.exe
2e77c4b48dbb641ce166674dcc33a371d0d53e92236e959dbddd364de1c24a10  target/release/veyra-desktop.exe
a69ca0df3a6b80b90f7a874cd0fce4a04c4b49cef51fb80add39011c02fb10ad  target/release/bundle/nsis/Veyra_0.1.0_x64-setup.exe
```

The honest V0.1 boundary remains local and single-daemon: the bearer is administrative root for one
OS account, registered in-process adapters are trusted code, and a privileged attacker can rewrite
both SQLite and its local anchor. Unknown external crash outcomes still require manual recovery;
authority consumption is atomic per effect rather than across a whole multi-effect plan; process
replacement between the final digest and spawn remains an OS-call race; protocol preconditions are
reserved but rejected; retained staging artifacts need lifecycle policy; and the remaining
per-transaction/high-volume verification paths still need streaming pagination before very large
journals.

## 2026-08-24 - OSS maintainer and supply-chain baseline

- Retired and deleted the bootstrap-only `goal.md`. `AGENTS.md` is now the canonical human/AI
  maintainer contract: it defines architecture and security invariants, an OSS change matrix,
  dependency and release discipline, companion documentation/tests for every public change, and an
  explicit prohibition on recreating `goal.md` or performing remote maintainer actions without
  authority. `.github/copilot-instructions.md` routes compatible AI tooling to the same contract.
- Added structured bug, feature, and usage-question forms, a security-safe support route, a pull
  request template, `SUPPORT.md`, `RELEASING.md`, and a maintainer checklist for repository-host
  settings. `CODEOWNERS`, funding, package owners, and signing identities remain intentionally absent
  until real maintainers configure them.
- Added the deterministic `oss:check` gate. Its initial baseline made 269 assertions over
  community-health files, AI instructions, public Rust/npm discovery metadata, exact license copies,
  retired-file absence, workflow permissions, immutable 40-character Action SHAs, version comments,
  and disabled checkout credential persistence.
- Added the post-build `package:check` gate. It inspects the actual Cargo package inventory for all
  seven publishable crates and `npm pack --dry-run --json` output for both public npm packages,
  requiring self-contained README/license/source or distribution content and rejecting local state,
  generated junk, and undeclared files.
- Added JavaScript/TypeScript CodeQL analysis, dependency review on every pull request,
  and OpenSSF Scorecard SARIF publication. Release packaging now includes README/license material,
  verifies cross-platform checksums, creates Sigstore-backed provenance inside the job that actually
  built each binary, and creates the tagged GitHub Release without replacing an existing version.
  All external Actions are pinned to reviewed release commit SHAs with least-privilege job
  permissions.
- Corrected every repository, badge, clone, issue, package, and attestation URL from the nonexistent
  placeholder organization location to the actual public origin, `tang-vu/veyra`.

Final local verification on the committed-source candidate used the installed GNU Rust toolchain
because this host still lacks the Windows MSVC linker:

```text
$env:VEYRA_RUST_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; .\scripts\verify.ps1
corepack pnpm package:check
actionlint 1.7.12 .github/workflows/*.yml
```

The full workspace gate passed 109 Rust tests and 15 JavaScript/TypeScript/UI tests, generated and
checked all 16 protocol schemas, built public Rust documentation with warnings denied, passed Cargo
advisory/license/source policy, found no production npm vulnerability at high severity, built the
frontend, and passed the OSS and package-archive gates. The eval result is 63 passed, 1
environment-limited, and 0 failed; EV-008 remains the documented unprivileged-Windows symlink
fixture and runs on Linux CI. The deterministic demo committed one effect, authenticated one
receipt, passed one verification, checked 39 audit events, rolled back, and removed the workspace
file. The five workflow files also passed actionlint 1.7.12 after the downloaded checker itself was
verified with GitHub artifact attestation.

After explicit maintainer authorization, the OSS baseline was pushed to `tang-vu/veyra`. The remote
Linux full gate, Windows MSVC gate, CodeQL analysis, and OpenSSF Scorecard workflow all completed
successfully on commit `33273fb`. The public repository now has its canonical description and five
focused topics, a 100% GitHub community-health profile, private vulnerability reporting, Dependabot
alerts and active security updates, secret scanning with push protection, read-only default workflow
tokens, and a selected-actions policy that host-enforces full commit SHA references. GitHub-owned
Actions plus the pinned pnpm and OpenSSF Scorecard Actions are the only allowed sources.

Active repository rulesets now require pull requests, resolved conversations, linear history, and
the Linux, Windows, dependency-review, and CodeQL checks on `main`; force pushes and deletion are
blocked with no standing administrator bypass. Approval count remains zero while the repository has
only one direct maintainer. A separate `v*` tag ruleset restricts creation, update, force-update, and
deletion to the repository owner. Merge commits are disabled, merged branches are deleted, and future
GitHub Releases are immutable. Release automation now creates a draft, attaches and verifies all
assets, and only then publishes it.

The new read-only `corepack pnpm oss:host-check` first failed on all missing protections, then passed
69 assertions after the host configuration was applied. The API-visible maintainer audit found one
direct administrator and no deploy keys, webhooks, environments, or secret alerts. After dependency
graph indexing completed, GitHub surfaced `GHSA-wrw7-89jp-8q8g` for Tauri's Linux-only transitive
`glib 0.18.5`; Dependabot confirmed `0.18.5` is the latest resolvable version while the fix begins at
`0.20.0`. The alert remains open rather than being dismissed for scorekeeping, and
[issue #4](https://github.com/tang-vu/veyra/issues/4) records the dependency path, current exposure,
controls, upstream references, and exit criteria. Independent approval, CODEOWNERS review, and
last-push approval also remain unavailable with one maintainer. Remaining human/roadmap work is
explicit: no transferable project-private conduct contact or signing identity exists, signed
release tags are therefore not required yet, package/recovery ownership needs periodic manual
review, and platform code signing plus an attested multi-ecosystem SBOM remain future work. No tag,
release, or registry package was created.

## 2026-08-24 - OpenSSF finding triage and continuous boundary fuzzing

The post-baseline Scorecard run was successful but correctly retained seven diagnostics. They were
reviewed individually instead of being dismissed for a cleaner dashboard:

- branch protection scores below maximum because a sole author cannot supply an independent
  approval, CODEOWNERS review, or last-push approval without inventing another maintainer;
- the security-policy check found policy text but no direct reporting link;
- no recognized fuzzing integration existed;
- the vulnerability check counted 17 RustSec/OSV entries in Tauri's target-specific GTK3 dependency
  family, while Dependabot exposed the one medium `glib` alert tracked in issue #4;
- code-review history has no independent approved changesets yet;
- the repository is younger than 90 days; and
- no OpenSSF Best Practices self-assessment has been submitted by a real project owner.

The two source-actionable findings are now addressed without changing runtime behavior. `SECURITY.md`
links directly to GitHub private vulnerability reporting. An isolated, non-published `fuzz/`
workspace adds pinned `cargo-fuzz 0.13.2`, `libfuzzer-sys 0.4.13`, and a dated nightly toolchain.
`canonical_protocol` covers arbitrary canonical JSON/digest stability; `resource_scope` covers
component-aware filesystem and HTTP containment plus exact process and generic scopes. Inputs,
timeouts, input length, and RSS are bounded. Pull requests and `main` run 30-second sessions per
target, while the weekly schedule runs five minutes per target. Dependabot monitors the separate
lockfile, Cargo license policy explicitly accepts libFuzzer's NCSA component, and the AI maintainer
contract requires future parsing or containment changes to preserve the relevant target.

Local Ubuntu WSL verification compiled both harnesses with warnings denied and completed 10,000
inputs per target without a crash or timeout. The canonical target reached 1,071 coverage edges and
the resource target reached 348. The full Windows GNU project gate then passed 109 Rust tests, 15
JavaScript/TypeScript/UI tests, all 16 schemas, seven Rust and two npm package archives, dependency
policy, 64 eval scenarios (`63` passed, `1` environment-limited, `0` failed), and the deterministic
commit/verify/rollback demo. `oss:check` passed 314 assertions, the fuzz dependency policy passed
advisories/licenses/sources, and actionlint 1.7.12 accepted all six workflows.

The first protected pull-request run completed `Fuzz security boundaries` successfully in 2m20s.
The active `Protect main` ruleset now requires that exact context alongside Linux, Windows MSVC,
dependency review, and CodeQL, with no bypass actor; the read-only hosted gate passes 71 assertions.
The tracked `glib` alert remains open, and no tag, release, registry package, reviewer identity,
signing identity, or Best Practices attestation was fabricated as part of this work.

## 2026-08-24 - atomic CodeQL Action maintenance

After Dependabot re-indexed the hardened repository, it opened pull requests #7 through #10 for the
four `github/codeql-action/*` entry points independently. Updating `init`, `autobuild`, or `analyze`
alone failed with an explicit loaded-version/running-version mismatch; the green `upload-sarif`
update did not make a partial family upgrade safe. This exposed a maintenance flaw rather than a
project-code regression.

All four entry points now use the verified upstream `v4.37.8` commit
`db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28`. Dependabot groups the family with
`github/codeql-action/*`, and the human/AI contract plus `oss:check` require exactly one reference
to each entry point with one common SHA and release comment. Future partial upgrades therefore fail
the source policy even if a single component appears independently mergeable.

Pre-push verification passed Prettier, actionlint 1.7.12 across all six workflows, the expanded
`oss:check` (`321` assertions), and the read-only hosted gate (`71` assertions). GitHub's tag API was
followed through the annotated `v4.37.8` tag to its target commit, whose commit verification reports
`valid`.

## 2026-08-24 - minimum Node compatibility and deterministic tooling updates

The first Dependabot cycle also opened PR #1 for Prettier 3.9.6 and PR #2 for `@types/node` 26.2.0.
The Prettier update is within major version 3; its only source effect is the formatter's new canonical
layout for one `JsonValue` union. The Node type update is intentionally not equivalent: the public
manifests promise Node 22 support, while merging Node 26 declarations could allow code that passes
type-checking but is absent from supported runtimes.

The workspace now tests the current Node 22 LTS patch from `.node-version-min`, keeps the default
maintainer toolchain in `.node-version`, pins direct and transitive Node declarations to the latest
22.x type release, and tells Dependabot not to propose an isolated type-major change. The human/AI
contract requires a deliberate compatibility migration before changing that major. The source gate
checks the engine, both runtime pins, direct type version, pnpm override, workflow identity, and
Dependabot policy as one contract.

Local verification passed frozen pnpm installation and supply-chain policy, Prettier, TypeScript
checks and lint, 15 JavaScript/TypeScript/UI tests, frontend and SDK builds, seven Rust plus two npm
archive checks, production audit with no known vulnerability, actionlint 1.7.12, and `oss:check`
with 342 assertions. Before the new hosted context existed, `oss:host-check` failed with exactly the
missing `JavaScript gate (Node 22)` and exact-required-set assertions, proving that host drift cannot
be silently reported as complete.

## 2026-08-24 - v0.1.0 release candidate

- Closed the accumulated changelog under a dated `0.1.0` section and added curated versioned release
  notes with artifact inventory, checksum/provenance commands, package-registry status, the local
  single-daemon trust boundary, unsigned-installer disclosure, and the tracked GTK/`glib` advisory.
- Added an executable release contract that keeps the annotated tag, Cargo workspace, all four npm
  workspace versions, Tauri bundle version, changelog links, and `docs/releases/vX.Y.Z.md` aligned.
  Both normal CI and the tag workflow run it; a tag checkout additionally proves the tag resolves to
  the exact checked-out commit.
- Extended tagged releases with an SPDX 2.3 multi-ecosystem repository dependency snapshot exported
  from GitHub's dependency graph, a sibling SHA-256 file, and a build-provenance attestation. The job
  fails rather than claiming tag scope if `main` has moved beyond the tag commit. Release notes state
  that this is a repository/build dependency snapshot, not a per-binary inventory.
- The publish job now requires curated notes before creating its draft, prepends them to GitHub's
  generated change list, attaches README, license, changelog, release notes, binaries, installer,
  checksums, and SBOM, and publishes only after every checksum validates. The build jobs execute the
  CLI version, daemon help, and deterministic reversible demo directly from each packaged Linux and
  Windows archive before upload.

Release-candidate verification completed successfully on the installed Windows GNU toolchain:

```text
$env:VEYRA_RUST_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; .\scripts\verify.ps1
corepack pnpm release:check
corepack pnpm oss:check
actionlint 1.7.12
cargo +stable-x86_64-pc-windows-gnu build --release -p veyra-cli -p veyra-server --locked
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; corepack pnpm desktop:build
```

The complete gate passed 109 Rust tests, 15 JavaScript/TypeScript/UI tests, 16 generated schemas,
seven Rust and two npm package archives, dependency policy, formatting, public Rust documentation,
and the deterministic commit/verify/rollback demo. The regenerated release-revision eval result is
63 passed, 1 environment-limited, and 0 failed; EV-008 remains the documented unprivileged-Windows
symlink fixture and runs in Linux CI. `release:check` passed 18 assertions and the expanded
`oss:check` passed 369. A locally repacked Windows archive ran `veyra 0.1.0`, daemon help, and the
complete commit/verify/rollback demo successfully after extraction. The downloaded actionlint 1.7.12
binary was verified against both its upstream
SHA-256 list and GitHub artifact attestation before all six workflows passed linting.

Local unsigned artifact evidence is packaging-only because this host lacks the supported MSVC
linker. The protected pull request and tag workflow remain authoritative for Linux and Windows MSVC
release artifacts:

```text
c1dec48f1789165755151bf5341ebf49d9b41aadb7a36bcd2740656012f579c9  target/release/veyra.exe
ae891ea858daf9e11670b8d2a38baa59bef7f3d9906ab5e200b8d9b163435fe0  target/release/veyra-server.exe
5e5774fb70b100847f3db2c4e8a81df0423f236ac77fbff7e9de12353bb0782e  target/release/veyra-desktop.exe
6577a44fc23375eb6583b230ced6a7e304386de5f5379891958e6338945901fd  target/release/bundle/nsis/Veyra_0.1.0_x64-setup.exe
```

No tag, GitHub Release, registry package, signing identity, independent maintainer review, or Best
Practices self-attestation was fabricated during release preparation. Those hosted or human actions
remain separate evidence.

## 2026-08-24 - v0.1.0 publication recovery

The annotated `v0.1.0` tag was created at the reviewed merge commit
`8226d69af7471755357d71c6169509bde240c478`. Its contract, Linux and Windows archives, packaged
smoke tests, Windows NSIS installer, checksums, artifact attestations, and uploads passed in the tag
workflow. GitHub's Dependency Graph SBOM endpoint returned HTTP 500 in both the original job and its
bounded failed-job retry, so the dependent publish job stayed skipped and no draft or public Release
was created.

Recovery now removes that default-branch API dependency. A full-SHA-pinned Anchore SBOM Action
(`v0.24.0`, Apache-2.0, verified upstream commit
`e22c389904149dbc22b58101806040fa8d37a610`) runs pinned Syft 1.42.3 against the exact checkout and
rejects an SPDX snapshot unless it contains both Cargo and npm package URLs. An explicit
`release_tag` dispatch is accepted only from protected `main`; the release contract proves the
existing tag is annotated and resolves to the checkout before all platform artifacts are rebuilt,
smoke-tested, checksummed, and attested. The tag is never moved or recreated, and publication still
fails closed if any draft or public release already exists.

A local two-worktree recovery simulation used the immutable tag as product source and the reviewed
recovery commit as release control. Its 24-assertion recovery contract passed, its manifest recorded
both distinct commits, and Syft produced SPDX 2.3 with 829 packages (636 Cargo and 170 npm) while
including zero files from the release-control checkout. The complete project gate subsequently
passed 109 Rust tests, 15 JavaScript/TypeScript/UI tests, 16 generated schemas, seven Rust plus two
npm package archives, 63 passing evals, one documented environment-limited eval, and zero failed
evals. `release:check` passed 21 assertions, `oss:check` passed 411, and actionlint 1.7.12 accepted all
six workflows.

## 2026-08-24 - v0.1.0 published release evidence

The protected recovery implementation was squash-merged through pull request
[#14](https://github.com/tang-vu/veyra/pull/14) at release-control commit
`0529ff49a8948a898b5dd1da0b08e1e9726096cf`, with all nine required pull-request checks passing and
no administrator bypass. Its main-branch CI, CodeQL, fuzz, and OpenSSF Scorecard runs also passed. A
build-only [release dry run](https://github.com/tang-vu/veyra/actions/runs/32742309960) then passed the
release contract, exact-tag SBOM generation, Linux and Windows archive builds and packaged smoke
tests, and the unsigned Windows NSIS build while correctly skipping publication.

The authorized [recovery release run](https://github.com/tang-vu/veyra/actions/runs/32743621982)
completed successfully from protected `main`. It rebuilt product artifacts from the unchanged
annotated tag source commit `8226d69af7471755357d71c6169509bde240c478`, while using the separately
recorded protected release-control commit above. Every build, packaged smoke test, checksum,
artifact attestation, release-manifest attestation, and final publish step passed. The resulting
[Veyra v0.1.0 release](https://github.com/tang-vu/veyra/releases/tag/v0.1.0) is public, latest,
non-prerelease, and GitHub-immutable, with 14 uploaded assets.

All 14 assets were downloaded again from the public Release for independent post-publication
verification. The five sibling checksum files matched the downloaded Linux archive, Windows
archive, unsigned NSIS installer, SPDX document, and release manifest. The manifest's 12-file
pre-manifest inventory matched every recorded byte size and SHA-256 digest, and bound the source tag,
release-control revision, recovery mode, workflow ref, and run attempt. GitHub/Sigstore provenance
verification passed for all five primary artifacts while requiring the exact `release.yml` signer,
release-control digest, `refs/heads/main` source ref, and GitHub-hosted runner:

```text
bc5c1148e86992508128ef7d1a58a630cb84aeda511e29830db6c97481e3cd5e  veyra-linux-x86_64.tar.gz
7f6f5f0ad5bdd5f3643eac0e0b197bc250c67f98cb2f973aab1fed45b8be1646  veyra-windows-x86_64.zip
d61a4062bb0d3cbcf7bfa1fa9c2e74245c5d8241cdc9f0d5c6fa8e7a7aaf9025  Veyra_0.1.0_x64-setup.exe
caf152928ffc46ad70f2ba8021b5a0d05a345a2501061743eee45a8f7215f142  veyra-v0.1.0.spdx.json
68e8fbece53174ed46efa322ae9b3c8c09561609a381e859048b2f96a455cbad  veyra-v0.1.0.release-manifest.json
```

The downloaded Windows archive and Linux archive under Ubuntu WSL each ran `veyra 0.1.0`, daemon
help, and the complete JSON demo successfully. Both demos committed one effect, authenticated one
receipt, passed one verification, checked 39 audit events, rolled back, and removed the workspace
file. The downloaded SPDX 2.3 document contains 829 packages, including 636 Cargo and 170 npm PURLs,
and no file from the recovery control checkout.

Publication does not remove the documented project limits. The Windows installer and binaries lack
a platform signing identity, crates and npm packages are not yet registry-published, independent
review and CODEOWNERS enforcement require additional real maintainers, and the genuine medium
Tauri/GTK `glib 0.18` advisory remains open and tracked in
[issue #4](https://github.com/tang-vu/veyra/issues/4) rather than being dismissed.
