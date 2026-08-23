/** Wire types for `veyra.protocol/v1`. JSON Schema in `@veyra/protocol-schema` is authoritative. */

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };
export type Id = string;
export type Timestamp = string;

export type PrincipalKind = "human" | "agent" | "service";
export interface Principal {
  id: Id;
  display_name: string;
  kind: PrincipalKind;
}

export type ResourceScope =
  | { kind: "filesystem"; workspace: string; path: string }
  | { kind: "filesystem_set"; workspace: string; paths: string[] }
  | {
      kind: "http";
      scheme: string;
      domain: string;
      port: number | null;
      path_prefix: string;
    }
  | { kind: "process"; executable: string; workdir: string }
  | { kind: "generic"; namespace: string; resource: string };

export interface Intent {
  schema_version: string;
  id: Id;
  principal_id: Id;
  summary: string;
  requested_resources: ResourceScope[];
  context: Record<string, JsonValue>;
  created_at: Timestamp;
}

export type InputValue =
  | { kind: "public"; value: JsonValue }
  | { kind: "secret_ref"; provider: string; key: string; redacted: string };

export type Condition =
  | { kind: "file_exists"; path: string; expected: boolean }
  | { kind: "file_sha256"; path: string; digest: string }
  | { kind: "http_status"; status: number }
  | { kind: "output_sha256"; digest: string }
  | { kind: "custom"; name: string; parameters: JsonValue };

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Reversibility = "reversible" | "compensatable" | "irreversible";

export type EffectPreview =
  | {
      kind: "filesystem";
      operation: string;
      path: string;
      before_sha256: string | null;
      after_sha256: string | null;
      unified_diff: string | null;
    }
  | {
      kind: "http";
      method: string;
      url: string;
      headers: Record<string, string>;
      body_sha256: string | null;
    }
  | {
      kind: "process";
      executable: string;
      args: string[];
      workdir: string;
      environment_keys: string[];
    }
  | { kind: "custom"; media_type: string; value: JsonValue }
  | { kind: "pending" };

export interface CapabilityRequirement {
  adapter: string;
  operation: string;
  resource: ResourceScope;
  constraints: Record<string, string>;
}

export interface OperationSpec {
  adapter: string;
  operation: string;
  inputs: Record<string, InputValue>;
  resource: ResourceScope;
}

export interface Effect {
  schema_version: string;
  id: Id;
  causal_parent: {
    intent_id: Id;
    plan_id: Id;
    step_id: Id;
    effect_id: Id | null;
  };
  principal_id: Id;
  adapter: string;
  operation: string;
  inputs: Record<string, InputValue>;
  resource: ResourceScope;
  preconditions: Condition[];
  expected_postconditions: Condition[];
  risk: RiskLevel;
  reversibility: Reversibility;
  preview: EffectPreview;
  idempotency_key: string;
  timeout_ms: number;
  retry: {
    max_attempts: number;
    backoff_ms: number;
    retryable_errors: string[];
  };
  required_capabilities: CapabilityRequirement[];
  inverse: OperationSpec | null;
}

export interface Step {
  id: Id;
  summary: string;
  effects: Effect[];
}

export interface Plan {
  schema_version: string;
  id: Id;
  intent_id: Id;
  planner: string;
  steps: Step[];
  created_at: Timestamp;
}

export interface Capability {
  id: Id;
  principal_id: Id;
  intent_id: Id | null;
  transaction_id: Id | null;
  adapter: string;
  operations: string[];
  resources: ResourceScope[];
  constraints: Record<string, string>;
  not_before: Timestamp;
  expires_at: Timestamp;
  nonce: string;
  max_uses: number;
  issued_at: Timestamp;
}

export type PolicyOutcome = "allow" | "require_approval" | "deny";
export interface PolicyDecision {
  id: Id;
  effect_id: Id;
  outcome: PolicyOutcome;
  reasons: string[];
  capability_ids: Id[];
  effect_digest: string;
  decided_at: Timestamp;
}

export interface ApprovalRequest {
  id: Id;
  transaction_id: Id;
  effect_id: Id;
  effect_digest: string;
  risk: RiskLevel;
  resource: ResourceScope;
  preview: EffectPreview;
  nonce: string;
  created_at: Timestamp;
  expires_at: Timestamp;
}

export interface ApprovalGrant {
  id: Id;
  request_id: Id;
  transaction_id: Id;
  approver_id: Id;
  effect_digest: string;
  nonce: string;
  granted_at: Timestamp;
  expires_at: Timestamp;
}

export type TransactionState =
  | "draft"
  | "planned"
  | "preflighted"
  | "awaiting_approval"
  | "approved"
  | "staged"
  | "executing"
  | "verifying"
  | "committed"
  | "denied"
  | "failed"
  | "compensating"
  | "rolled_back"
  | "partially_compensated"
  | "cancelled"
  | "manual_recovery";

export interface Transaction {
  schema_version: string;
  id: Id;
  intent_id: Id;
  plan_id: Id;
  state: TransactionState;
  effect_ids: Id[];
  receipt_ids: Id[];
  revision: number;
  created_at: Timestamp;
  updated_at: Timestamp;
  manual_recovery_reason: string | null;
}

export interface Execution {
  id: Id;
  transaction_id: Id;
  effect_id: Id;
  effect_digest: string;
  attempt: number;
  started_at: Timestamp;
  completed_at: Timestamp | null;
  outcome: string | null;
}

export interface Receipt {
  id: Id;
  execution_id: Id;
  transaction_id: Id;
  effect_id: Id;
  effect_digest: string;
  outcome: string;
  result_digest: string;
  result: JsonValue;
  issued_at: Timestamp;
  signer_key_id: string;
  authentication: string;
}

export interface VerificationCheck {
  condition: Condition;
  passed: boolean;
  message: string;
}

export interface Verification {
  id: Id;
  transaction_id: Id;
  effect_id: Id;
  checks: VerificationCheck[];
  passed: boolean;
  verified_at: Timestamp;
}

export interface Compensation {
  id: Id;
  transaction_id: Id;
  effect_id: Id;
  reversibility: Reversibility;
  restored: boolean;
  details: JsonValue;
  completed_at: Timestamp;
}

export interface AuditEvent {
  id: Id;
  transaction_id: Id | null;
  sequence: number;
  event_type: string;
  causal_parent: string | null;
  payload: JsonValue;
  previous_hash: string;
  hash: string;
  recorded_at: Timestamp;
}

export interface AuditVerification {
  valid: boolean;
  events_checked: number;
  first_invalid_sequence: number | null;
  message: string;
}

export interface Submission {
  intent: Intent;
  plan: Plan;
  transaction: Transaction;
}

export interface PreviewOutcome {
  plan: Plan;
  decisions: PolicyDecision[];
  approval_requests: ApprovalRequest[];
  transaction: Transaction;
}

export interface ApprovalOutcome {
  grant: ApprovalGrant;
  transaction: Transaction;
  all_effects_approved: boolean;
}

export interface RunOutcome {
  transaction: Transaction;
  receipts: Receipt[];
  verifications: Verification[];
  recoveries: Compensation[];
  committed: boolean;
}

export interface RollbackOutcome {
  transaction: Transaction;
  recoveries: Compensation[];
}

export interface TransactionBundle {
  transaction: Transaction;
  intent: Intent;
  plan: Plan;
  policy_decisions: PolicyDecision[];
  approval_requests: ApprovalRequest[];
  approval_grants: ApprovalGrant[];
  executions: Execution[];
  receipts: Receipt[];
  verifications: Verification[];
  compensations: Compensation[];
  events: AuditEvent[];
}

export interface DemoSeed {
  human: Principal;
  agent: Principal;
  capability: Capability;
  submission: Submission;
}

export interface RecoveryRecord {
  transaction_id: Id;
  state: TransactionState;
  action: "resume_safe" | "manual_recovery";
}
