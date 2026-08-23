# Veyra implementation plan

Status legend: `[ ]` pending, `[~]` active, `[x]` verified.

## Milestone 1 — trusted contract and state machine

- [x] Define the complete versioned protocol/domain model and canonical digests.
- [x] Implement typed transaction transitions and invariant/property tests.
- [x] Generate JSON Schema and golden fixtures from Rust types.

## Milestone 2 — policy, journal, and filesystem vertical slice

- [x] Implement deny-by-default, scoped expiring capabilities and content-addressed approvals.
- [x] Implement the SQLite hash-chained append-only journal, snapshots, idempotency, receipt authentication, and recovery classification.
- [x] Implement staged filesystem read/create/patch/move/delete with containment, TOCTOU checks, verification, and rollback.
- [x] Complete an end-to-end filesystem transaction through the CLI and real API.

## Milestone 3 — clients and remaining adapters

- [x] Build the versioned daemon API, machine-readable CLI, and TypeScript SDK.
- [x] Build HTTP and disabled-by-default process adapters with strict policy and limits.
- [x] Add deterministic and OpenAI-compatible planners with strict plan validation.
- [x] Connect the Tauri desktop control plane to the real daemon API.

## Milestone 4 — hardening and release quality

- [ ] Exercise crash boundaries, concurrency/idempotency, malicious adapters, replay, receipt forgery, spoofing, and secret redaction.
- [ ] Add and run at least 20 machine-readable eval scenarios.
- [ ] Complete OSS, architecture, protocol, security, adapter, API/CLI, and release documentation.
- [ ] Inspect desktop UI at multiple viewports and run supported smoke/E2E coverage.
- [ ] Run the complete verification matrix, review as maintainer/security engineer, fix findings, and produce the final report.
