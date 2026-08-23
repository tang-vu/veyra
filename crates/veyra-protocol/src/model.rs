//! Versioned Veyra domain model.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ApprovalGrantId, ApprovalRequestId, AuditEventId, CapabilityId, CompensationId, EffectId,
    EffectInputs, ExecutionId, IntentId, PlanId, PolicyDecisionId, PrincipalId, ReceiptId, StepId,
    TransactionId, VerificationId, canonical_digest,
};

/// A human, agent, service, or system component that can request or approve work.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// Stable principal identifier.
    pub id: PrincipalId,
    /// Display-only name.
    pub display_name: String,
    /// Principal class used by policy.
    pub kind: PrincipalKind,
}

/// Principal classes recognized by the protocol.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A person operating Veyra.
    Human,
    /// An AI or deterministic planning agent.
    Agent,
    /// A local or remote service identity.
    Service,
    /// A trusted kernel component.
    System,
}

/// A user's requested outcome, before an agent proposes effects.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Protocol identifier.
    pub schema_version: String,
    /// Stable intent identifier.
    pub id: IntentId,
    /// Requesting principal.
    pub principal_id: PrincipalId,
    /// Plain-language requested outcome.
    pub summary: String,
    /// Maximum resource envelope the planner may propose.
    pub requested_resources: Vec<ResourceScope>,
    /// Non-secret planner context.
    #[serde(default)]
    pub context: BTreeMap<String, Value>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// A validated proposal of steps and effects. A plan itself has no authority.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Protocol identifier.
    pub schema_version: String,
    /// Stable plan identifier.
    pub id: PlanId,
    /// Source intent.
    pub intent_id: IntentId,
    /// Planner implementation identifier.
    pub planner: String,
    /// Ordered steps.
    pub steps: Vec<Step>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// A causal grouping of one or more effects.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Stable step identifier.
    pub id: StepId,
    /// Human-readable rationale.
    pub summary: String,
    /// Ordered effects in this step.
    pub effects: Vec<Effect>,
}

/// Causal ancestry used in the journal and UI timeline.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalParent {
    /// Intent that caused this effect.
    pub intent_id: IntentId,
    /// Plan that proposed this effect.
    pub plan_id: PlanId,
    /// Step containing this effect.
    pub step_id: StepId,
    /// Optional prior effect whose output directly caused this effect.
    pub effect_id: Option<EffectId>,
}

/// The complete immutable effect proposal that policy and approval bind to.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    /// Protocol identifier.
    pub schema_version: String,
    /// Stable effect identifier.
    pub id: EffectId,
    /// Causal ancestry.
    pub causal_parent: CausalParent,
    /// Principal on whose behalf the effect would execute.
    pub principal_id: PrincipalId,
    /// Registered adapter name.
    pub adapter: String,
    /// Adapter operation name.
    pub operation: String,
    /// Typed public data and opaque secret references.
    pub inputs: EffectInputs,
    /// Exact resource affected.
    pub resource: ResourceScope,
    /// Reserved preconditions. The V0.1 kernel rejects non-empty values until an explicit
    /// adapter evaluation contract is available.
    pub preconditions: Vec<Condition>,
    /// Postconditions required for a committed transaction.
    pub expected_postconditions: Vec<Condition>,
    /// Declared risk used by approval policy.
    pub risk: RiskLevel,
    /// Honest rollback or compensation class.
    pub reversibility: Reversibility,
    /// Structured preview shown to the approver.
    pub preview: Preview,
    /// Stable key used to suppress duplicate execution.
    pub idempotency_key: String,
    /// Hard adapter timeout.
    pub timeout_ms: u64,
    /// Bounded retry policy.
    pub retry: RetryPolicy,
    /// Capabilities the effect claims it needs. Policy independently verifies them.
    pub required_capabilities: Vec<CapabilityRequirement>,
    /// Optional inverse/compensation request.
    pub inverse: Option<OperationSpec>,
}

impl Effect {
    /// Canonical content digest used by approvals, staging, executions, and receipts.
    ///
    /// # Errors
    ///
    /// Returns [`crate::CanonicalError`] if an input cannot be represented as canonical JSON.
    pub fn content_digest(&self) -> Result<String, crate::CanonicalError> {
        canonical_digest(self)
    }
}

/// An exact or prefix-bounded resource identifier.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceScope {
    /// A normalized path relative to a named workspace root.
    Filesystem {
        /// Configured workspace name.
        workspace: String,
        /// Normalized path relative to the workspace.
        path: String,
    },
    /// Multiple exact paths in one workspace, used by operations such as move.
    FilesystemSet {
        /// Configured workspace name.
        workspace: String,
        /// Ordered, normalized paths relative to the workspace.
        paths: Vec<String>,
    },
    /// An HTTP origin and path prefix.
    Http {
        /// Lowercase `http` or `https` scheme.
        scheme: String,
        /// Lowercase DNS name without credentials.
        domain: String,
        /// Explicit non-default port.
        port: Option<u16>,
        /// Normalized absolute path prefix.
        path_prefix: String,
    },
    /// An exact executable and normalized working directory.
    Process {
        /// Exact configured executable identifier or canonical path.
        executable: String,
        /// Normalized configured working directory.
        workdir: String,
    },
    /// Extension namespace for third-party adapters.
    Generic {
        /// Globally unique adapter namespace.
        namespace: String,
        /// Adapter-defined normalized resource identifier.
        resource: String,
    },
}

/// A typed condition vocabulary reserved for preconditions and evaluated for postconditions.
///
/// The V0.1 kernel rejects non-empty precondition lists until adapters have a versioned evaluation
/// contract; supported postconditions are still evaluated after execution.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// A relative filesystem path must exist or not exist.
    FileExists {
        /// Workspace-relative normalized path.
        path: String,
        /// Required existence state.
        expected: bool,
    },
    /// File contents must have a precise SHA-256 digest.
    FileSha256 {
        /// Workspace-relative normalized path.
        path: String,
        /// Required lowercase SHA-256 digest.
        digest: String,
    },
    /// An HTTP response status must match.
    HttpStatus {
        /// Required HTTP status code.
        status: u16,
    },
    /// Adapter output must have the declared digest.
    OutputSha256 {
        /// Required lowercase SHA-256 digest.
        digest: String,
    },
    /// Versioned third-party condition.
    Custom {
        /// Versioned condition name.
        name: String,
        /// Secret-safe condition parameters.
        parameters: Value,
    },
}

/// Severity used for policy and UI decisions.
#[derive(
    Clone, Copy, Debug, Deserialize, JsonSchema, Ord, PartialEq, PartialOrd, Eq, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Read-only or readily restored work with narrow scope.
    Low,
    /// Mutating but bounded work with reliable recovery.
    Medium,
    /// Broad, externally visible, or best-effort recoverable work.
    High,
    /// Irreversible or safety-critical work.
    Critical,
}

/// The recovery guarantee an adapter can honestly provide.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The adapter can restore the prior state under its documented atomicity boundary.
    Reversible,
    /// The adapter can attempt a semantic inverse, but restoration is not guaranteed.
    Compensatable,
    /// No rollback or compensation is claimed.
    Irreversible,
}

/// Structured effect preview.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Preview {
    /// Filesystem diff or operation description.
    Filesystem {
        /// Filesystem operation.
        operation: String,
        /// Workspace-relative path.
        path: String,
        /// Original digest, if the path exists.
        before_sha256: Option<String>,
        /// Proposed digest, if the path will exist.
        after_sha256: Option<String>,
        /// Bounded UTF-8 unified diff when content is textual.
        unified_diff: Option<String>,
    },
    /// Redacted outbound HTTP request.
    Http {
        /// Uppercase HTTP method.
        method: String,
        /// Allowlisted URL without user information.
        url: String,
        /// Headers with credential values replaced by markers.
        headers: BTreeMap<String, String>,
        /// Digest of the outbound body, if present.
        body_sha256: Option<String>,
    },
    /// Exact argv without shell interpolation.
    Process {
        /// Exact executable.
        executable: String,
        /// SHA-256 of the executable bytes observed during preflight.
        executable_sha256: String,
        /// Exact argument vector.
        args: Vec<String>,
        /// Exact working directory.
        workdir: String,
        /// Names, but never values, of passed environment entries.
        environment_keys: Vec<String>,
    },
    /// Safe adapter-defined preview.
    Custom {
        /// Versioned media type describing the value.
        media_type: String,
        /// Secret-safe preview body.
        value: Value,
    },
    /// Planner placeholder. Preflight must replace this before approval.
    Pending,
}

/// Bounded retry configuration.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Includes the initial attempt and must be at least one.
    pub max_attempts: u8,
    /// Base delay used for bounded exponential backoff.
    pub backoff_ms: u64,
    /// Stable adapter error codes that may be retried.
    pub retryable_errors: Vec<String>,
}

/// Capability shape requested by an effect.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    /// Adapter name.
    pub adapter: String,
    /// Operation name.
    pub operation: String,
    /// Exact requested resource.
    pub resource: ResourceScope,
    /// Constraint names the policy engine must understand.
    #[serde(default)]
    pub constraints: BTreeMap<String, String>,
}

/// A scoped, expiring grant of tool authority.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Stable capability identifier.
    pub id: CapabilityId,
    /// Principal to whom the grant is bound.
    pub principal_id: PrincipalId,
    /// Optional intent binding.
    pub intent_id: Option<IntentId>,
    /// Optional transaction binding.
    pub transaction_id: Option<TransactionId>,
    /// Exact adapter.
    pub adapter: String,
    /// Allowed operations.
    pub operations: Vec<String>,
    /// Allowed resource scopes.
    pub resources: Vec<ResourceScope>,
    /// Enforced policy constraints.
    pub constraints: BTreeMap<String, String>,
    /// Grant is invalid before this timestamp.
    pub not_before: DateTime<Utc>,
    /// Grant is invalid at or after this timestamp.
    pub expires_at: DateTime<Utc>,
    /// Unique anti-replay nonce.
    pub nonce: String,
    /// Maximum successful effect authorizations.
    pub max_uses: u32,
    /// Creation timestamp.
    pub issued_at: DateTime<Utc>,
}

/// Result of a deny-by-default policy evaluation.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    /// Stable decision identifier.
    pub id: PolicyDecisionId,
    /// Effect evaluated.
    pub effect_id: EffectId,
    /// Outcome.
    pub outcome: PolicyOutcome,
    /// Stable, human-readable reasons.
    pub reasons: Vec<String>,
    /// Capabilities sufficient for the decision.
    pub capability_ids: Vec<CapabilityId>,
    /// Canonical effect digest seen by policy.
    pub effect_digest: String,
    /// Evaluation timestamp.
    pub decided_at: DateTime<Utc>,
}

/// Policy outcome before execution.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Live capabilities are sufficient and policy does not require human approval.
    Allow,
    /// Capabilities are sufficient, but approval is required by risk policy.
    RequireApproval,
    /// Authority or constraints are insufficient.
    Deny,
}

/// Approval challenge containing the immutable effect content digest.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    /// Stable request identifier.
    pub id: ApprovalRequestId,
    /// Bound transaction.
    pub transaction_id: TransactionId,
    /// Bound effect.
    pub effect_id: EffectId,
    /// Canonical digest of the complete preflighted effect.
    pub effect_digest: String,
    /// Risk shown to the approver.
    pub risk: RiskLevel,
    /// Exact scope shown to the approver.
    pub resource: ResourceScope,
    /// Preflight preview shown to the approver.
    pub preview: Preview,
    /// Unique anti-replay nonce.
    pub nonce: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Challenge expiry.
    pub expires_at: DateTime<Utc>,
}

/// An approver's time-bounded grant for an exact approval challenge.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrant {
    /// Stable grant identifier.
    pub id: ApprovalGrantId,
    /// Challenge being answered.
    pub request_id: ApprovalRequestId,
    /// Transaction binding copied from the challenge.
    pub transaction_id: TransactionId,
    /// Approving principal.
    pub approver_id: PrincipalId,
    /// Effect digest copied from the challenge.
    pub effect_digest: String,
    /// Challenge nonce copied exactly.
    pub nonce: String,
    /// Creation timestamp.
    pub granted_at: DateTime<Utc>,
    /// Grant expiry.
    pub expires_at: DateTime<Utc>,
}

/// A single adapter execution attempt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    /// Stable execution identifier.
    pub id: ExecutionId,
    /// Transaction binding.
    pub transaction_id: TransactionId,
    /// Effect binding.
    pub effect_id: EffectId,
    /// Immutable effect digest at execution time.
    pub effect_digest: String,
    /// One-based attempt number.
    pub attempt: u8,
    /// Start timestamp.
    pub started_at: DateTime<Utc>,
    /// Completion timestamp, absent while in flight.
    pub completed_at: Option<DateTime<Utc>>,
    /// Stable adapter outcome code when complete.
    pub outcome: Option<String>,
}

/// Kernel-issued, authenticated evidence of an adapter result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Stable receipt identifier.
    pub id: ReceiptId,
    /// Execution being attested.
    pub execution_id: ExecutionId,
    /// Transaction binding.
    pub transaction_id: TransactionId,
    /// Effect binding.
    pub effect_id: EffectId,
    /// Immutable effect digest.
    pub effect_digest: String,
    /// Stable adapter outcome code.
    pub outcome: String,
    /// Digest of redacted adapter result data.
    pub result_digest: String,
    /// Redacted, bounded adapter result.
    pub result: Value,
    /// Issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Local receipt authentication key identifier.
    pub signer_key_id: String,
    /// HMAC-SHA-256 over the canonical receipt payload, excluding this field.
    pub authentication: String,
}

/// Outcome of checking declared postconditions.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// Stable verification identifier.
    pub id: VerificationId,
    /// Transaction binding.
    pub transaction_id: TransactionId,
    /// Effect binding.
    pub effect_id: EffectId,
    /// Individual postcondition results.
    pub checks: Vec<VerificationCheck>,
    /// True only when every declared check passed.
    pub passed: bool,
    /// Completion timestamp.
    pub verified_at: DateTime<Utc>,
}

/// Result for one postcondition.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCheck {
    /// Condition that was checked.
    pub condition: Condition,
    /// Whether it passed.
    pub passed: bool,
    /// Redacted observation or failure explanation.
    pub message: String,
}

/// A rollback or best-effort compensation attempt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Compensation {
    /// Stable compensation identifier.
    pub id: CompensationId,
    /// Transaction binding.
    pub transaction_id: TransactionId,
    /// Original effect.
    pub effect_id: EffectId,
    /// Recovery class actually attempted.
    pub reversibility: Reversibility,
    /// Whether prior state was restored to the adapter's verified boundary.
    pub restored: bool,
    /// Redacted adapter evidence.
    pub details: Value,
    /// Completion timestamp.
    pub completed_at: DateTime<Utc>,
}

/// Optional inverse or compensation operation declared by an effect.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSpec {
    /// Adapter name.
    pub adapter: String,
    /// Operation name.
    pub operation: String,
    /// Secret-safe inputs.
    pub inputs: EffectInputs,
    /// Exact recovery resource.
    pub resource: ResourceScope,
}

/// Persisted transaction state.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// Protocol identifier.
    pub schema_version: String,
    /// Stable transaction identifier.
    pub id: TransactionId,
    /// Source intent.
    pub intent_id: IntentId,
    /// Source plan.
    pub plan_id: PlanId,
    /// Current state.
    pub state: TransactionState,
    /// Ordered effect identifiers.
    pub effect_ids: Vec<EffectId>,
    /// Successful receipts.
    pub receipt_ids: Vec<ReceiptId>,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last transition timestamp.
    pub updated_at: DateTime<Utc>,
    /// Reason requiring manual intervention, if applicable.
    pub manual_recovery_reason: Option<String>,
}

/// Explicit transaction states. Transitions are enforced by `veyra-core`.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// Intent accepted but no validated plan is bound.
    Draft,
    /// Validated plan bound.
    Planned,
    /// Adapter preflight and policy completed.
    Preflighted,
    /// Waiting for content-addressed approval.
    AwaitingApproval,
    /// Required approval grants are live.
    Approved,
    /// Changes prepared without applying external side effects.
    Staged,
    /// At least one effect may be in flight.
    Executing,
    /// Declared postconditions are being checked.
    Verifying,
    /// Every effect completed and every declared postcondition passed.
    Committed,
    /// Policy or a human denied execution.
    Denied,
    /// Execution or verification failed.
    Failed,
    /// Recovery operations are running.
    Compensating,
    /// All supported effects were restored.
    RolledBack,
    /// Some but not all effects were restored or compensated.
    PartiallyCompensated,
    /// Cancelled before an unsafe in-flight boundary.
    Cancelled,
    /// Crash evidence is insufficient for safe automatic recovery.
    ManualRecovery,
}

impl TransactionState {
    /// Whether no normal forward transition may leave this state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Denied
                | Self::Failed
                | Self::RolledBack
                | Self::PartiallyCompensated
                | Self::Cancelled
                | Self::ManualRecovery
        )
    }
}

/// One immutable event in the hash-chained append-only journal.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// Stable event identifier.
    pub id: AuditEventId,
    /// Transaction binding, absent only for journal-wide maintenance events.
    pub transaction_id: Option<TransactionId>,
    /// Per-journal, one-based monotonic sequence.
    pub sequence: u64,
    /// Stable event kind.
    pub event_type: String,
    /// Safe causal link to the effect or prior event that caused this event.
    pub causal_parent: Option<String>,
    /// Redacted canonical event payload.
    pub payload: Value,
    /// Previous event hash, or the fixed genesis hash for sequence one.
    pub previous_hash: String,
    /// SHA-256 over all event fields and the previous hash.
    pub hash: String,
    /// Event timestamp.
    pub recorded_at: DateTime<Utc>,
}

/// Result of verifying the complete persisted journal chain.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerification {
    /// True only if every link, sequence, and event hash is valid.
    pub valid: bool,
    /// Number of verified events.
    pub events_checked: u64,
    /// First invalid sequence, when corruption is detected.
    pub first_invalid_sequence: Option<u64>,
    /// Human-readable result safe for normal logs.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_recovery_and_commit_are_terminal() {
        assert!(TransactionState::Committed.is_terminal());
        assert!(TransactionState::ManualRecovery.is_terminal());
        assert!(!TransactionState::Executing.is_terminal());
    }

    #[test]
    fn unknown_effect_fields_are_rejected() {
        let value = serde_json::json!({"schema_version":"x","id":EffectId::new(),"extra":true});
        assert!(serde_json::from_value::<Effect>(value).is_err());
    }
}
