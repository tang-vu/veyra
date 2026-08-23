# Progress

## 2026-08-23 — baseline

- Repository contained only the untracked specification `goal.md`; no implementation or history was present.
- Environment: Rust/Cargo 1.96.0, Node 24.14.1, pnpm 11.20.0, Windows 10; global `cargo-tauri` is not installed.
- Reviewed current official Tauri 2 setup, Axum 0.8 serving, SQLite crate guidance, pnpm workspace guidance, and the OpenAI Responses structured-output contract.
- Selected a Rust 2024 workspace with a dependency MSRV of 1.85 and a pnpm workspace. Tauri is kept as a project-local dependency.
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
