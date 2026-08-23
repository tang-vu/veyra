# Contributing to Veyra

Veyra welcomes focused fixes, adversarial tests, adapter improvements, and protocol proposals. By
participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are licensed
under Apache-2.0.

## Setup

Install Rust through `rustup`, Node.js 22+, and enable Corepack. Desktop work additionally requires
the platform packages listed in the Tauri 2 prerequisites.

```sh
corepack enable
corepack pnpm install --frozen-lockfile
cargo test --workspace --all-targets --all-features --locked
corepack pnpm test
```

On Windows, install the Visual Studio C++ Build Tools for the default MSVC target. A MinGW toolchain
can run the Rust gates and can be useful for local Tauri builds
(`$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"`), but the supported Windows release
workflow uses MSVC and WebView2.

## Change discipline

Keep protocol, authority, persistence, and OS interaction in their existing crate boundaries. New
effects require typed inputs, exact resource scope, preflight behavior, idempotency semantics,
honest reversibility, verification, redaction, and adversarial tests. A planner or client must never
make authority decisions.

For a wire-level change, update the Rust type, regenerate schemas, add a compatibility fixture, and
write or amend a VEP. For a security-sensitive change, state which invariant it preserves and test
the failure path as well as success.

Run the complete gate before opening a pull request:

```text
# PowerShell 5+
./scripts/verify.ps1

# Bash
bash ./scripts/verify.sh
```

Use small commits with an imperative subject. Explain observable behavior, tests, compatibility
impact, and residual risk in the pull request. Generated schema files and the current eval result are
committed; build directories, credentials, local databases, and Playwright artifacts are not.

## Design proposals

Behavior that changes the trust model, protocol compatibility, persistence format, or adapter
contract should start as a VEP in `docs/protocol/` or an ADR in `docs/architecture/adr/`. Maintainers
evaluate proposals against least authority, recoverability, interoperability, and implementation
complexity—not feature count.
