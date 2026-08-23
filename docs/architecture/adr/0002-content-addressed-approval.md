# ADR-0002: Approve canonical preflighted effects

- Status: Accepted
- Date: 2026-08-23

## Context

Approving intent text or a plan ID permits the actual operation, resource, or preview to change after
the user sees it. JSON byte strings also have non-semantic formatting differences.

## Decision

Run non-mutating adapter preflight first, serialize the complete effect with RFC 8785/JCS canonical
JSON, and approve its SHA-256 digest. Bind the approval to a transaction, effect, expiring challenge,
single-use nonce, approver, exact resource, risk, and preview. Recompute and compare the digest at
execution.

## Consequences

Any meaningful mutation invalidates approval and replay is rejected. Preview generation becomes part
of the trusted adapter contract. Protocol changes that alter canonical content require explicit
compatibility handling.
