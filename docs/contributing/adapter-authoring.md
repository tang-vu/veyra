# Authoring an effect adapter

An adapter is the narrow bridge between a validated Veyra effect and an external side-effect domain.
It does not decide whether work is authorized. Registering an in-process adapter grants privileged
code access under the daemon's OS identity, so review and test it as part of the trusted computing
base.

The complete runnable example is [`examples/custom-adapter`](../../examples/custom-adapter/). It
implements a reversible in-memory counter and intentionally documents why volatile state is not
production recovery evidence.

## 1. Define a stable contract

Choose a namespaced adapter name and a small operation vocabulary. For each operation specify:

- accepted `ResourceScope` and the exact typed `InputValue` field set;
- intrinsic checks, supported postconditions, and their observation scope;
- a bounded, secret-safe preview format;
- idempotency behavior and where the durable outcome lives;
- exact verification observations;
- `reversible`, `compensatable`, or `irreversible` semantics;
- timeout, output, and retry bounds.

Do not call an operation reversible merely because an approximate inverse exists. Restoration must
preserve unrelated changes and be verifiable.

## 2. Implement the lifecycle

Implement `veyra_executor::EffectAdapter`:

```rust
#[async_trait::async_trait]
impl EffectAdapter for MyAdapter {
    fn name(&self) -> &'static str { "org.example.widget" }
    fn validate(&self, effect: &Effect) -> Result<(), AdapterError> { /* shape only */ }
    async fn preflight(&self, effect: &Effect, ctx: &AdapterContext)
        -> Result<AdapterPreflight, AdapterError> { /* observe, never mutate */ }
    async fn stage(&self, effect: &Effect, ctx: &AdapterContext)
        -> Result<StagedEffect, AdapterError> { /* bind restoration data */ }
    async fn execute(&self, effect: &Effect, staged: &StagedEffect, ctx: &AdapterContext)
        -> Result<AdapterResult, AdapterError> { /* one bounded side effect */ }
    async fn verify(&self, effect: &Effect, staged: &StagedEffect,
        result: &AdapterResult, ctx: &AdapterContext)
        -> Result<Vec<VerificationCheck>, AdapterError> { /* independent observations */ }
    async fn rollback(&self, effect: &Effect, staged: &StagedEffect, ctx: &AdapterContext)
        -> Result<AdapterRecovery, AdapterError> { /* restore without clobbering */ }
}
```

`validate` must reject wrong adapter/operation names, resource variants, input types, unsupported
conditions, unknown or ignored input names, understated risk, dishonest reversibility, unsafe retry
settings, and every capability constraint the adapter cannot actually enforce, without touching
external state. Mutating operations must not accept `RiskLevel::Low`; broad, externally visible, or
irreversible operations need a correspondingly higher floor. V0.1 rejects all non-empty
`preconditions` at the kernel and accepts only one attempt with zero backoff and no retryable error
names; adapters are never automatically reinvoked by the kernel. Call
`veyra_executor::validate_capability_constraints(effect, &[...])` with only the adapter-specific
constraint names whose semantics you enforce; the helper recognizes kernel-wide caveats and rejects
everything else.

`preflight` observes the current state and returns the exact display content that will enter the
approved effect digest. Never mutate in preflight. Redact headers, payload fields, and other values
that could contain secrets.

`stage` must re-observe TOCTOU-sensitive state and compare it with the approved preview. Its
`StagedEffect` must repeat adapter, effect ID, and `effect.content_digest()`. Persist enough
secret-safe evidence to determine safe recovery after restart; do not put live credentials in it.

`execute` validates the stage binding again, crosses the declared boundary once, enforces local
limits, and returns a bounded result. The kernel provides the durable idempotency reservation, but an
external service should also receive its idempotency key when supported.

`verify` must observe actual post-state, not trust success text returned by execute. Return one check
covering each declared postcondition; a false condition is a successful observation with
`passed: false`. Reject postcondition variants or paths the adapter cannot evaluate inside the exact
effect resource. Do not use a convenient second resource as an observation oracle.

`rollback` operates from durable stage evidence, in reverse-order orchestration. Before restoring,
confirm that current state is still the post-state produced by this effect. If another actor changed
it, return `restored: false` instead of clobbering their work.

## 3. Secrets and errors

Accept secret references in the protocol and resolve them as late as possible through
`AdapterContext.secrets`. Keep `SecretValue` lifetimes short. Normal `Display` errors, results,
staging data, receipts, and observations must never include resolved bytes, unbounded or
secret-bearing process output, or unredacted response bodies. Add a sentinel-secret test across
success and every error path. Public input and custom-condition field names that look like
credentials are rejected by the kernel; do not invent a second cleartext secret channel. A
`SecretRef` must retain the literal `[REDACTED]` marker and bounded provider/key identifiers.

## 4. Register and authorize

Call `AdapterRegistry::register(Arc::new(adapter))` while constructing a kernel. Duplicate names are
rejected. Then add planner/schema support only for the documented operations. Registration does not
grant authority: callers still need a capability matching name, operation, structured resource,
constraints, principal and bindings.

## 5. Required tests

At minimum cover malformed shape, unknown operation and input field, risk understatement,
unsupported/out-of-scope conditions, preview without mutation, TOCTOU at stage and execute,
duplicate idempotent invocation at the system boundary, output limits, timeouts, verification
failure, crash-safe staged-data decoding, non-clobbering rollback, partial compensation, and secret
redaction. Property-test resource containment when it has hierarchy.

Run:

```sh
cargo test -p veyra-custom-adapter-example
cargo clippy -p veyra-custom-adapter-example --all-targets -- -D warnings
```
