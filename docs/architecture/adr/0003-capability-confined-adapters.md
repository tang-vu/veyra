# ADR-0003: Capability-confined typed adapters, no implicit shell

- Status: Accepted
- Date: 2026-08-23

## Context

A generic command tool obscures resources, makes useful previews difficult, and cannot honestly
promise rollback. String-based path checks and shell interpolation also expand injection risk.

## Decision

Use an explicit adapter registry and a lifecycle of validate, preflight, stage, execute, verify, and
rollback. Effects declare typed resource scopes and reversibility. The filesystem adapter operates
through a capability-based directory root. HTTP uses exact allowlists. Process execution is disabled
by default, receives argv rather than a command line, and is always irreversible in this release.

## Consequences

The kernel can reason about authority and recovery without knowing each tool. New operations require
real adapter engineering instead of prompt text. In-process adapters are trusted privileged code and
must be audited; the trait alone is not a sandbox.
