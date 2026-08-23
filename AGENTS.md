# Veyra contributor notes

## Build and verify

- Rust: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-targets --all-features --locked`.
- TypeScript: `pnpm install --frozen-lockfile`, `pnpm check`, `pnpm lint`, `pnpm test`, `pnpm build`.
- Demo: `cargo run --locked -p veyra-cli -- demo --json` (add `--directory <path>` to preserve state).
- Full local gate: `./scripts/verify.ps1` from PowerShell 5+ (or `bash ./scripts/verify.sh`).

## Boundaries

- `veyra-protocol` owns versioned wire/domain types; it has no kernel dependencies.
- `veyra-policy` only decides authority. It never performs effects.
- `veyra-journal` is append-only persistence and recovery evidence.
- `veyra-executor` owns adapters and OS/network interaction. Adapters do not grant authority.
- `veyra-core` is the trusted state machine/orchestrator.
- CLI, SDK, and desktop request transitions through the same versioned local API. The API bearer is
  an administrative root credential; never expose it to a model or an untrusted web client.

## Security invariants

- Deny by default: no effect executes without a live, matching capability.
- Approval binds to the canonical digest of the exact effect.
- Paths are relative, lexically clean, traversed through no-follow directory handles, and rechecked at
  preflight, capture, execution, verification, and rollback.
- A retry with the same idempotency key returns the recorded outcome; it does not execute twice.
- Journal hashes and receipt MACs are verified before they are trusted.
- Raw secrets are represented by references and never serialized into plans, receipts, logs, or audit exports.
- Shell interpolation is never implicit. Process execution is disabled unless explicitly configured.
- “Reversible” is reserved for operations with verified restoration under documented adapter
  preconditions; compensation is reported separately.

## Conventions and done

- Keep dependencies small, errors typed, serialized enums snake_case, and public protocol changes versioned.
- Add adversarial tests with every authorization or filesystem change.
- Never weaken a containment, digest, journal, or idempotency check to make a test pass.
- A change is done only when relevant Rust/TypeScript checks pass, docs and schemas are updated, and `PROGRESS.md` records evidence and limitations.
