#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"

cargo_command=(cargo)
if [[ -n "${VEYRA_RUST_TOOLCHAIN:-}" ]]; then
  cargo_command+=("+${VEYRA_RUST_TOOLCHAIN}")
fi

"${cargo_command[@]}" fmt --all -- --check
"${cargo_command[@]}" clippy --workspace --all-targets --all-features --locked -- -D warnings
"${cargo_command[@]}" test --workspace --all-targets --all-features --locked
"${cargo_command[@]}" run --locked -p veyra-protocol --example generate-schema -- packages/protocol-schema/schema
node packages/protocol-schema/scripts/verify-generated.mjs
git diff --exit-code -- packages/protocol-schema/schema

if ! cargo deny --version >/dev/null 2>&1; then
  echo "cargo-deny is required; install it with: cargo install cargo-deny --version 0.20.2 --locked" >&2
  exit 78
fi
cargo deny check advisories bans licenses sources --hide-inclusion-graph

corepack pnpm install --frozen-lockfile
corepack pnpm format
corepack pnpm check
corepack pnpm lint
corepack pnpm test
corepack pnpm build
corepack pnpm audit --prod --audit-level high
corepack pnpm eval

"${cargo_command[@]}" run --locked -p veyra-cli -- demo --json
