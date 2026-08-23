# Veyra evaluations

This directory contains the machine-readable security and recovery scenario catalog and its latest
observed result. Run it from the repository root:

```sh
corepack pnpm eval
```

`scenarios/security-and-recovery.json` maps each expectation to an observable Rust test, TypeScript
test, focused verbose desktop test, or deterministic demo gate. `run.mjs` runs the locked,
all-feature workspace suite and refuses to report success when a named probe is missing or a gate
fails. The focused desktop gate keeps named UI-concurrency evidence observable even though the
normal Vitest summary hides passing test names. The runner writes `results/latest.json` using
`veyra.eval-results/v1`.

The result statuses are:

- `passed` — the gate succeeded and the named probe was observed.
- `failed` — the gate failed, the probe disappeared, or the end-to-end demo invariant was false.
- `environment_limited` — the catalog explicitly identifies a platform prerequisite that cannot be
  exercised on this host. This never converts another failed gate or scenario into a pass.

The current catalog intentionally emphasizes authority, containment, crash recovery, evidence
integrity, bounded untrusted data, secret handling, and non-clobbering restoration. Add a scenario
whenever a new security invariant or previously missed failure mode is introduced.
