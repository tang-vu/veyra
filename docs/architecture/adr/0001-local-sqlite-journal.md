# ADR-0001: Local SQLite journal with a hash chain

- Status: Accepted
- Date: 2026-08-23

## Context

The first vertical slice needs durable crash recovery, optimistic snapshots, uniqueness constraints,
and inspectable audit evidence without introducing distributed infrastructure.

## Decision

Use one SQLite database in WAL mode with full synchronous durability. Store immutable typed objects,
revisioned transaction snapshots, staged descriptors, capability uses, approval nonces, idempotency
reservations, and an append-only event table. Hash each canonical event with its previous hash.
Authenticate receipts separately with a local HMAC key.

## Consequences

Transactions and uniqueness constraints are simple and locally reproducible. The journal detects
ordinary corruption and edits. One daemon process per database is the supported model. The chain is
not a blockchain, trusted timestamp, remote transparency log, or defense against an attacker able to
replace both database and local trust material.
