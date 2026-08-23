# Changelog

All notable changes are documented here. The project follows Semantic Versioning and Keep a
Changelog conventions.

## [Unreleased]

### Added

- Complete `veyra.protocol/v1` domain model, generated JSON Schemas, canonical content digests, and
  strict secret-reference encoding.
- Explicit transaction state machine and deny-by-default capability/approval policy.
- SQLite WAL journal with hash-chain verification, authenticated receipts, idempotency reservations,
  redacted exports, and conservative crash recovery.
- Staged reversible filesystem adapter, allowlisted HTTP adapter, and disabled-by-default argv-only
  process adapter.
- Model-independent planner trait, deterministic fixture planner, and optional OpenAI
  Responses-compatible planner.
- Authenticated loopback API, machine-readable CLI, typed TypeScript SDK, and real React/Tauri control
  plane.
- Deterministic end-to-end demo, custom adapter example, adversarial test suite, and 39-scenario eval
  harness.
- Architecture, protocol, security, contributor, governance, and release documentation.

### Security

- Approval grants bind the canonical digest of the exact preflighted effect and consume one nonce.
- Filesystem containment uses clean relative paths, component-wise no-follow capability handles,
  exact captured/prepared-file digest checks, atomic no-replace commits, collision-safe staging, and
  non-clobbering rollback.
- Data and workspace directories require disjoint canonical roots; newly created Unix API tokens use
  owner-only permissions.
- Planner, adapter, CLI, and SDK inputs/outputs are byte/depth bounded; HTTP DNS results and
  duplicate/request/response headers are bounded; reflected HTTP and process-output secrets are
  redacted without amplification.
- Plan validation requires prior causal parents and bounded, adapter-unique idempotency keys;
  recovery uses all available durable stages and reports missing evidence as partial compensation.
- The journal maintains a transactional local count/head anchor so deleting the current audit tail
  is detected as well as mutation, gaps, and broken links.

[Unreleased]: https://github.com/veyra-project/veyra/commits/main
