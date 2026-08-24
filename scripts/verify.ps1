$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repository

$toolchain = @()
if ($env:VEYRA_RUST_TOOLCHAIN) {
    $toolchain = @("+$($env:VEYRA_RUST_TOOLCHAIN)")
}

function Assert-LastExitCode([string]$step) {
    if ($LASTEXITCODE -ne 0) {
        throw "$step failed with exit code $LASTEXITCODE"
    }
}

& cargo @toolchain fmt --all -- --check
Assert-LastExitCode "Rust formatting"

& cargo @toolchain clippy --workspace --all-targets --all-features --locked -- -D warnings
Assert-LastExitCode "Rust lint"

& cargo @toolchain test --workspace --all-targets --all-features --locked
Assert-LastExitCode "Rust tests"

$env:RUSTDOCFLAGS = "-D warnings"
& cargo @toolchain doc --workspace --all-features --no-deps --locked
Assert-LastExitCode "Rust documentation"

& cargo @toolchain run --locked -p veyra-protocol --example generate-schema -- packages/protocol-schema/schema
Assert-LastExitCode "Schema generation"
& node packages/protocol-schema/scripts/verify-generated.mjs
Assert-LastExitCode "Generated schema inventory"

& git diff --exit-code -- packages/protocol-schema/schema
Assert-LastExitCode "Generated schema drift check"

& cargo deny --version
if ($LASTEXITCODE -ne 0) {
    throw "cargo-deny is required; install it with: cargo install cargo-deny --version 0.20.2 --locked"
}
& cargo deny check advisories bans licenses sources --hide-inclusion-graph
Assert-LastExitCode "Rust dependency policy"

& corepack pnpm install --frozen-lockfile
Assert-LastExitCode "pnpm install"
& corepack pnpm oss:check
Assert-LastExitCode "OSS policy"
& corepack pnpm release:check
Assert-LastExitCode "Release contract"
& corepack pnpm format
Assert-LastExitCode "Formatting"
& corepack pnpm check
Assert-LastExitCode "Type checking"
& corepack pnpm lint
Assert-LastExitCode "TypeScript lint"
& corepack pnpm test
Assert-LastExitCode "TypeScript tests"
& corepack pnpm build
Assert-LastExitCode "TypeScript build"
& corepack pnpm package:check
Assert-LastExitCode "Package archives"
& corepack pnpm audit --prod --audit-level high
Assert-LastExitCode "JavaScript dependency audit"
& corepack pnpm eval
Assert-LastExitCode "Security and recovery evals"

& cargo @toolchain run --locked -p veyra-cli -- demo --json
Assert-LastExitCode "Deterministic demo"
