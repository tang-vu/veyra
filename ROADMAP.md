# Roadmap

This roadmap communicates direction, not a delivery promise. Security correctness and a coherent
execution boundary take priority over adapter count.

## 0.1 — local reversible vertical slice

- Versioned protocol, deny-by-default capabilities, exact approval, explicit state machine
- SQLite journal, recovery classification, authenticated receipts, redacted audit export
- Reversible confined filesystem adapter; bounded HTTP and disabled process adapters
- Fixture and OpenAI Responses-compatible planners
- Authenticated daemon, CLI, TypeScript SDK, Tauri control plane, eval suite, and OSS baseline

## Next

- Stable migration tooling for protocol and journal revisions
- A supervised manual-recovery workflow with evidence capture and operator acknowledgements
- Out-of-process adapter isolation and signed adapter metadata
- OS keychain integration and stronger local token lifecycle
- Per-client agent/operator credentials and cryptographic human approval identity
- Policy-driven retention and garbage collection for durable filesystem staging artifacts
- Cursor pagination/streaming for the remaining per-transaction bundle path and high-volume audit
  verification; transaction, audit-event/export, and recovery list pages are implemented
- A versioned precondition-evaluation contract; V0.1 deliberately rejects non-empty preconditions
- An authenticated audit anchor outside SQLite or optional remote transparency sink
- First-class MCP interception example and A2A receipt exchange example
- Broader Windows reparse-point and network-filesystem adversarial testing
- Native no-replace rename support for filesystems that do not provide regular-file hard links
- Removal of Tauri's transitive GTK3/`glib 0.18` audit exception when upstream supports a fixed stack
- Reproducible, signed release provenance once project signing infrastructure exists

## Before 1.0

- Define compatibility guarantees and a deprecation window
- External security review of capability matching, canonical approval, filesystem containment, and
  crash recovery
- Stabilize adapter certification tests and protocol conformance fixtures
- Decide whether multi-process coordination belongs in scope; retain the single-daemon constraint if
  it cannot be made simple and auditable
- Publish operational hardening and backup/restore guidance

## Not planned as core scope

Veyra does not aim to become a model router, general agent framework, prompt marketplace, arbitrary
code sandbox, blockchain, or distributed workflow engine.
