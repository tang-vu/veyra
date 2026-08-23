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
