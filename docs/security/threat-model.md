# Threat model

## Scope and assets

Veyra protects the authority represented by capabilities, the exact content a human approved,
workspace containment, at-most-once effect intent, raw credentials at adapter boundaries, and the
integrity of local transaction evidence. It runs as one local daemon under one OS account.

Trusted components are the kernel, policy engine, journal, bundled adapter implementations, their
configuration, the receipt key and API token files, SQLite and cryptographic dependencies, and the
host operating system. In-process third-party adapters join this trusted computing base.

Untrusted inputs include prompts, model responses, intent context, API callers without a valid token,
workspace names/content, symlinks, HTTP responses, process output, repeated requests, and crash
timing. The current bearer token is an administrative root credential: its holder can register
principals, issue or revoke capabilities, and nominate a human principal for approval. The kernel
still rejects illegal transitions and false policy or verification outcomes, but V0.1 does not
cryptographically authenticate separate human clients. A planner must never receive this bearer.

## Security invariants

1. No effect executes without sufficient live, scoped capability authority.
2. The executed effect digest equals the content approved after preflight.
3. A committed transaction has passing declared postconditions.
4. Reuse of an idempotency key cannot duplicate a known execution.
5. Any mutation, gap, reorder, or broken link in the event chain, or mismatch in an audit-bound
   durable snapshot, is detected by verification.
6. Bundled filesystem operations cannot escape the configured workspace.
7. Normal plans, errors, receipts, logs, and audit exports do not contain resolved secret bytes.

## Threat analysis

| Threat                                   | Controls                                                                                                                                                                                                                                                                              | Residual risk                                                                                                                                                |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Prompt injection seeks tool authority    | Planner receives intent but not capability issuance or adapter handles; kernel independently checks scope and live authority                                                                                                                                                          | A human can still approve a harmful but accurately displayed effect                                                                                          |
| Confused deputy / capability escalation  | Grants bind principal plus optional intent/transaction, adapter, operation, structured resource, constraints, expiry, nonce, and uses                                                                                                                                                 | A deliberately broad grant is broad authority; the issuer remains responsible                                                                                |
| Approval replay or post-preview mutation | Single-use nonce, expiry, transaction binding, canonical effect digest repeated in request/grant/execution; capability uses, nonce row, and audit evidence commit atomically per effect                                                                                               | Compromise of the human principal or local daemon is out of scope                                                                                            |
| Path traversal                           | Clean relative paths only; capability-based root handle; structured scope comparison                                                                                                                                                                                                  | OS/filesystem implementation defects remain possible                                                                                                         |
| Symlink/junction escape                  | Traverse each component through capability-directory handles; final opens disable symlink following; repeat at preflight, staging, execution, verification, rollback                                                                                                                  | Windows reparse-point varieties and network filesystems deserve platform-specific review                                                                     |
| TOCTOU                                   | Digest staged observations, atomically capture mutation sources, recheck captured bytes, and commit destinations with no-replace hard links                                                                                                                                           | A same-account process with another open handle/hard link can mutate an inode after a check; OS-call races may force conservative failure or manual recovery |
| Duplicate execution after retry          | Unique durable idempotency reservation and serialized transaction operation; completion binds an authenticated receipt for the exact effect digest; stored result returned once known                                                                                                 | Crash after external effect but before durable outcome is unknowable and enters manual recovery                                                              |
| Crash in any phase                       | WAL/FULL durability, revisioned snapshots, staged evidence, phase classification, conservative resume rules                                                                                                                                                                           | Filesystem/drive lies about durability and host-wide rollback are out of scope                                                                               |
| Forged receipt                           | Bounded canonical receipt shape, exact effect/result digests, HMAC-SHA-256 with a local random key, and constant-time verification                                                                                                                                                    | An attacker reading the key can forge receipts; this is not hardware attestation or non-repudiation                                                          |
| Journal or snapshot tampering            | Canonical hash chain with sequence/previous-hash verification and local tail anchor; transactions, objects, capability facts, approval replay rows, stages, and idempotency state are checked against audit bindings in both directions; generic events cannot shadow reserved fields | An attacker who can rewrite the whole DB and its local anchor can construct a new chain; no authenticated external anchor or transparency log exists         |
| Malformed or malicious adapter           | Registry is explicit; kernel binds IDs/digests, bounds/depth-checks every evidence phase, requires complete postcondition coverage, and recovers on malformed verification                                                                                                            | An in-process adapter is privileged code and can bypass its own confinement. Review it before registration                                                   |
| Ignored input or condition semantics     | Planner inputs are exact-name only per bundled adapter; unsupported conditions fail validation; V0.1 rejects every non-empty precondition; filesystem postconditions stay inside effect scope                                                                                         | The protocol reserves preconditions for a future version, but V0.1 provides no precondition execution contract                                               |
| Secret leakage                           | Secret-reference wire type with a fixed redaction marker, credential-shaped public fields rejected, late resolver at adapter boundary, journal redaction, bounded control-safe client errors                                                                                          | A malicious adapter or compromised process memory can read resolved values; public inputs not identified as sensitive are intentionally persisted            |
| HTTP SSRF / DNS rebinding                | Exact configured scheme/origin/method/path rules, bounded DNS results with address pinning, private/special address rejection, redirects/retries disabled, bounded headers/body/time                                                                                                  | Trusted proxying, split DNS, service-side forwarding, and nominally safe methods that mutate server state need deployment-specific policy                    |
| Process injection / spoofed output       | Adapter disabled by default, direct argv only, exact executable/arguments/workdir/env rules, executable digest, shell binaries denied, bounded output/time                                                                                                                            | Enabled child code has Veyra's OS privileges; same-user replacement between the last digest and spawn remains an OS-call race                                |
| API theft or cross-origin use            | Loopback listener enforcement, random private-file bearer, exact CORS origins, bounded requests, constant-time token comparison                                                                                                                                                       | The bearer is administrative root; same-user malware can often read files/process memory or call loopback. This is not a multi-user boundary                 |
| Model provider data exposure             | Only the secret-safe intent is sent; key is a request header, output is byte/depth/schema bounded, redirects/retries are disabled, response errors are suppressed, storage is disabled                                                                                                | The configured provider sees intent public context; provider retention and transport beyond HTTPS depend on that provider                                    |

## Recovery semantics

V0.1 performs no automatic adapter retries: retry policy must declare one attempt, zero backoff, and
no retryable errors. Before `executing`, a repeated operator request or cancellation is safe if the
state-machine edge permits it. During `executing`, absence of a durable result does not prove absence
of an effect. Veyra marks the
idempotency reservation unknown and requires manual recovery. Although verification observation is
non-mutating, a restart during `verifying` is also normalized to manual recovery because persisted
adapter evidence may be incomplete. Recovery proceeds over every available durable stage in reverse
effect order and stops short of overwriting unrelated changes. Missing staging evidence or a refused
restoration produces the honest `partially_compensated` outcome.

## Operational guidance

- Run one daemon per database under a dedicated, minimally privileged OS account.
- Keep data and workspace on disjoint canonical roots; protect the data directory with OS ACLs.
- Treat the API bearer as administrative root and keep it out of prompts, models, remote web pages,
  logs, command-line URLs, and lower-trust clients.
- Keep capabilities short-lived and transaction-bound with `max_uses: 1` whenever possible.
- Leave process execution disabled unless an exact audited use case needs it.
- Restrict HTTP rules to the narrowest host, port, method, and path prefix.
- Verify the journal before trusting an audit export and back up the receipt key with the database.
- Treat `manual_recovery` as an incident requiring external observation, not a retry button.
- Protect and budget the workspace's reserved `.veyra/staging` tree. V0.1 retains restoration
  artifacts so committed work remains rollback-capable and does not yet implement retention/GC.
- Mutating filesystem effects require regular-file hard-link support inside the workspace for an
  atomic no-replace commit; unsupported filesystems fail without replacing the destination.

## Dependency advisory disposition

The multi-platform dependency graph includes Tauri's Linux GTK3 stack. Upstream currently pins
`glib 0.18.5`, which is covered by `RUSTSEC-2024-0429`; the defect is in
`VariantStrIter`/`array_iter_str`. Repository-wide source inspection confirms that neither Veyra nor
another resolved dependency calls that API, and this release produces a Windows desktop bundle, so
`deny.toml` carries one narrowly reasoned exception. Tauri's GTK3 and `rust-unic` transitives also
carry unmaintained notices with no safe upstream upgrade. The security gate still denies all known
vulnerabilities, direct unmaintained dependencies, other unsound advisories, wildcard dependencies,
unknown registries, unknown Git sources, and unapproved licenses. Remove the exception as soon as
Tauri moves off the affected GTK stack.

## Explicit non-goals

Veyra does not defend against a compromised kernel or OS, a malicious registered in-process adapter,
physical attacks, side channels, broad capabilities intentionally issued by a human, or side effects
outside adapter observability. It is not a sandbox for arbitrary code, a remote attestation system,
a multi-tenant authorization server, or a distributed ledger.
