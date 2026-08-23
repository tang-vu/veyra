/goal Build and thoroughly verify Veyra: a production-quality open-source
reversible execution kernel for AI agents. Continue working autonomously until
the vertical slice, security invariants, tests, documentation, demo, and
release artifacts defined below are complete and verified.

PROJECT IDENTITY

Name: Veyra
Repository: veyra
Tagline: Reversible execution for AI agents.
License: Apache-2.0

Core thesis:
AI agents must not receive unrestricted tools and merely promise to behave.
Every side effect must be represented as a typed effect, checked against
capabilities and policy, previewed when possible, explicitly approved according
to risk, executed with an audit trail, verified against postconditions, and
rolled back or compensated when possible.

Veyra is not another chatbot, agent framework, prompt collection, or desktop
clicking demo. It is an embeddable execution substrate between agents and tools.

AUTONOMY

- Inspect the repository and environment before deciding implementation details.
- If the repository is empty, initialize it completely.
- Research current official documentation for dependencies before choosing
  versions or APIs.
- Make reasonable architectural decisions without asking me.
- Ask only when credentials, destructive external actions, or an irreversible
  product choice truly requires me.
- Do not stop after planning or scaffolding.
- Do not claim something works without executing the relevant verification.
- Keep PLANS.md and PROGRESS.md current so work can resume after context loss.
- Create a concise, practical AGENTS.md containing build commands, architecture
  boundaries, conventions, security invariants, and definition of done.
- Make logical local commits when milestones are genuinely complete.
- Do not push, publish packages, create remote resources, or deploy externally.

ARCHITECTURE

Use a Rust workspace for the trusted core and a pnpm workspace for TypeScript.

Suggested structure; improve it when justified:

crates/
  veyra-core/          domain model and state machine
  veyra-policy/        capability and approval policy engine
  veyra-journal/       append-only event journal and SQLite persistence
  veyra-executor/      effect adapters, staging, execution and recovery
  veyra-protocol/      schemas, serialization and versioning
  veyra-server/        local daemon/API
  veyra-cli/           inspectable command-line interface
apps/
  desktop/             Tauri desktop application
packages/
  sdk-typescript/      ergonomic typed client
  protocol-schema/     generated JSON Schema and fixtures
examples/
  safe-workspace/      complete executable demo
  custom-adapter/      minimal third-party effect adapter
docs/
  architecture/
  protocol/
  security/
  contributing/
evals/
  scenarios/
  results/

Keep dependencies restrained. Prefer stable, established libraries. Avoid
premature distributed infrastructure.

DOMAIN MODEL

Design versioned types for at least:

- Principal
- Intent
- Plan
- Step
- Effect
- Capability
- PolicyDecision
- ApprovalRequest
- ApprovalGrant
- Execution
- Receipt
- Verification
- Compensation
- Transaction
- AuditEvent

Every effect must declare:

- stable ID and causal parent
- actor/principal
- adapter and operation
- typed inputs with secret-safe redaction
- exact resource scope
- preconditions
- expected postconditions
- risk level
- reversibility class:
  reversible | compensatable | irreversible
- preview representation
- idempotency key
- timeout and retry policy
- required capabilities
- optional inverse or compensation operation

Implement an explicit state machine. Invalid transitions must be impossible or
rejected with typed errors. A plausible flow is:

draft -> planned -> preflighted -> awaiting_approval -> approved -> staged ->
executing -> verifying -> committed

with terminal or recovery paths including denied, failed, compensating,
rolled_back, partially_compensated and cancelled.

Never describe arbitrary shell commands as truly reversible. Clearly distinguish
atomic rollback, best-effort compensation and irreversible effects.

SECURITY MODEL

Deny by default.

Implement scoped, expiring capability grants. Bind grants to the principal,
intent or transaction, adapter, operation, resources and relevant constraints.
Protect against replay. Make approval content-addressed so the approved effect
cannot silently mutate before execution.

Threat-model and test:

- prompt injection crossing into tool authority
- confused deputy behavior
- path traversal
- symlink escape
- TOCTOU changes between preview and execution
- capability escalation
- approval replay
- malicious or malformed adapters
- secret leakage through logs/errors
- forged receipts
- output spoofing
- duplicate execution after retry
- crashes during every transaction phase

Do not invent security guarantees that the implementation cannot provide.
Document trust boundaries and residual risks precisely.

INITIAL EFFECT ADAPTERS

Build a meaningful vertical slice:

1. Filesystem adapter
   - sandboxed workspace root
   - read, create, patch, move and delete
   - previews as structured diffs
   - path and symlink containment
   - staged changes before commit
   - rollback for supported operations

2. HTTP adapter
   - explicit domain/method allowlists
   - request preview with secret redaction
   - idempotency support
   - response size and timeout limits
   - irreversible or compensatable classification

3. Process adapter
   - disabled by default
   - explicit executable/argument/workdir/environment policy
   - time and output limits
   - no shell interpolation by default
   - honest non-reversibility classification
   - safe demo executor that does not require elevated privileges

Provide a clean adapter trait so external contributors can add adapters without
modifying the kernel.

JOURNAL AND RECOVERY

Use an append-only, hash-chained event journal persisted in SQLite.

- Persist enough state to recover after a daemon crash.
- Detect corrupted or missing journal links.
- Resume safely or move the transaction to a manual-recovery state.
- Ensure idempotency prevents accidental double execution.
- Provide a human-readable and JSON audit export.
- Redact secrets consistently.
- Include causal relationships explaining why each effect occurred.

Do not market the hash chain as a blockchain.

API AND CLI

Expose a versioned local API and a useful CLI.

Illustrative CLI experience:

veyra init
veyra intent submit ./examples/safe-workspace/intent.json
veyra plan show <id>
veyra tx preview <id>
veyra approval grant <id>
veyra tx run <id>
veyra tx inspect <id>
veyra tx rollback <id>
veyra audit verify
veyra demo

Commands must return useful exit codes and support machine-readable JSON output.
Generate API/schema documentation from authoritative types where practical.

DESKTOP APPLICATION

Build a polished Tauri desktop control plane, not a generic admin dashboard.

It must include:

- command/intent entry
- current transactions
- plan and effect inspection
- permission request showing exact scope and risk
- filesystem diff preview
- causal execution timeline
- verification results
- rollback/compensation controls
- searchable audit history
- clear empty, loading, error and recovery states
- keyboard accessibility and responsive layout
- dark and light themes

The desktop app must consume the same real local API as the CLI. Do not build a
fake frontend with disconnected mock data. A deterministic demo mode may seed
real local transactions through the API.

VISUAL DIRECTION

Aim for a restrained, premium systems-tool aesthetic: dense enough for experts,
understandable to non-experts, excellent typography, deliberate spacing and
clear risk colors. Avoid excessive gradients, glassmorphism, giant cards and
AI-generated marketing clichés.

Inspect the running UI at multiple viewport sizes. Fix visual defects rather
than assuming JSX implies good design.

MODEL INTEGRATION

Keep the trusted execution core model-independent.

Define a planner interface and provide:

- a deterministic fixture planner so every test/demo works without API keys
- one documented OpenAI-compatible provider adapter
- strict schema validation for model-generated plans
- rejection of unknown effects or resource scopes
- no model access to raw credentials

The model proposes effects. The trusted kernel authorizes and executes them.

TESTING

Build serious tests, not token tests written only to raise coverage:

- unit tests for state transitions and policy decisions
- property-based tests for security invariants
- schema compatibility/golden tests
- integration tests across daemon, database and adapters
- crash/failure injection at transaction boundaries
- concurrency and idempotency tests
- path/symlink adversarial tests
- API and CLI tests
- TypeScript SDK tests
- desktop smoke/E2E tests where the environment supports them

Create an eval suite with at least 20 scenarios covering safe success, denial,
approval mutation, crashes, rollback, partial compensation, replay and malicious
inputs. Produce machine-readable results.

Define explicit invariants, including:

- no effect executes without sufficient live capabilities
- approved effect content equals executed effect content
- a committed transaction satisfies declared verified postconditions
- retrying an idempotent effect cannot duplicate it
- journal tampering is detected
- no filesystem action escapes its workspace
- secrets never appear in normal audit exports

DOCUMENTATION AND OSS QUALITY

Create:

- exceptional README with problem, thesis, architecture, quick start and demo
- concise architecture diagram using Mermaid
- protocol specification VEP-0001
- threat model
- security policy and vulnerability reporting instructions
- contribution guide
- code of conduct
- governance and roadmap
- adapter authoring tutorial
- API/CLI reference
- comparison explaining that Veyra complements MCP/A2A/agent frameworks
- ADRs for important decisions
- changelog
- example policies and intents

Configure formatting, linting, CI, dependency auditing, license headers where
appropriate, release builds and reproducible local setup.

QUALITY LOOP

Work vertically:

1. Record baseline and plan.
2. Make the trusted core compile.
3. Complete one real filesystem transaction end to end through the CLI.
4. Add policy, approval, journal verification and recovery.
5. Connect the real API and desktop UI.
6. Expand adapters and SDK.
7. Harden security and failure handling.
8. Polish docs, UX and release artifacts.
9. Run the entire verification matrix.
10. Review the complete diff as a skeptical maintainer and security engineer.
11. Fix every high-confidence issue found.
12. Repeat verification until clean.

After each meaningful milestone, update PROGRESS.md with commands run, results,
known limitations and the next bottleneck.

DEFINITION OF DONE

Do not stop until:

- a fresh clone can follow README instructions successfully
- formatting, lint, type checking, tests and security checks pass
- the deterministic demo works without paid services or API keys
- a user can submit an intent, inspect effects, approve them, execute, verify,
  inspect receipts and roll back a supported filesystem transaction
- the desktop UI demonstrates that same real flow
- all eval scenarios pass or any environment-impossible case is explicitly
  documented with reproducible evidence
- no placeholder exists on a core execution path
- threat model and limitations are candid
- repository contains no secrets, generated junk or misleading claims
- final report lists implemented features, verification evidence, architecture
  decisions, remaining risks and the exact commands needed to run the demo

Prioritize depth, correctness and one unforgettable vertical slice over a large
set of shallow features.