//! Deny-by-default policy evaluation for scoped capabilities and approvals.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use subtle::ConstantTimeEq;
use thiserror::Error;
use veyra_protocol::{
    ApprovalGrant, ApprovalGrantId, ApprovalRequest, ApprovalRequestId, Capability, CapabilityId,
    Effect, PolicyDecision, PolicyDecisionId, PolicyOutcome, ResourceScope, Reversibility,
    RiskLevel, TransactionId,
};

/// Configuration for the built-in policy engine.
#[derive(Clone, Debug)]
pub struct PolicyConfig {
    /// Effects at or above this level require content-addressed approval.
    pub approval_threshold: RiskLevel,
    /// Adapters that may be authorized. Unlisted adapters are denied even with a capability.
    pub enabled_adapters: HashSet<String>,
    /// Maximum effect timeout accepted by kernel policy.
    pub maximum_timeout_ms: u64,
    /// Maximum lifetime accepted for a content-addressed approval request.
    pub maximum_approval_lifetime: Duration,
    /// Whether any irreversible effect can be authorized at all.
    pub allow_irreversible: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            approval_threshold: RiskLevel::Medium,
            enabled_adapters: ["filesystem", "http"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            maximum_timeout_ms: 30_000,
            maximum_approval_lifetime: Duration::minutes(10),
            allow_irreversible: false,
        }
    }
}

/// Persisted use/revocation facts supplied to policy evaluation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityStatus {
    /// Number of durably consumed authorization attempts, including fail-closed staging attempts.
    pub uses: u32,
    /// Whether the capability has been explicitly revoked.
    pub revoked: bool,
}

/// Deny-by-default evaluator. It has no adapter or persistence authority.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    /// Create a policy engine from explicit configuration.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Evaluate a complete effect against live capabilities.
    ///
    /// Every declared requirement must correspond exactly to the effect's adapter, operation,
    /// and resource, and at least one live capability must cover every requirement.
    pub fn evaluate(
        &self,
        effect: &Effect,
        transaction_id: TransactionId,
        intent_id: veyra_protocol::IntentId,
        capabilities: &[Capability],
        statuses: &HashMap<CapabilityId, CapabilityStatus>,
        now: DateTime<Utc>,
    ) -> PolicyDecision {
        let digest = effect
            .content_digest()
            .unwrap_or_else(|_| "unavailable".to_owned());
        let mut reasons = Vec::new();
        let mut matched = Vec::new();

        if !self.config.enabled_adapters.contains(&effect.adapter) {
            reasons.push(format!("adapter `{}` is disabled", effect.adapter));
        }
        if effect.timeout_ms == 0 || effect.timeout_ms > self.config.maximum_timeout_ms {
            reasons.push("effect timeout exceeds kernel policy".to_owned());
        }
        if effect.retry.max_attempts != 1
            || effect.retry.backoff_ms != 0
            || !effect.retry.retryable_errors.is_empty()
        {
            reasons.push(
                "automatic effect retries are disabled; use one attempt and durable idempotency"
                    .to_owned(),
            );
        }
        if effect.idempotency_key.trim().is_empty() {
            reasons.push("idempotency key is required".to_owned());
        }
        if effect.reversibility == Reversibility::Irreversible && !self.config.allow_irreversible {
            reasons.push("irreversible effects are disabled".to_owned());
        }
        if effect.required_capabilities.is_empty() {
            reasons.push("effect declares no capability requirement".to_owned());
        }

        for requirement in &effect.required_capabilities {
            if requirement.adapter != effect.adapter
                || requirement.operation != effect.operation
                || requirement.resource != effect.resource
            {
                reasons.push("capability requirement does not exactly describe the effect".into());
                continue;
            }

            let candidate = capabilities.iter().find(|capability| {
                statuses.get(&capability.id).is_some_and(|status| {
                    Self::capability_covers(
                        capability,
                        effect,
                        transaction_id,
                        intent_id,
                        *status,
                        &requirement.constraints,
                        now,
                    )
                })
            });
            if let Some(capability) = candidate {
                if !matched.contains(&capability.id) {
                    matched.push(capability.id);
                }
            } else {
                reasons.push(format!(
                    "no live capability covers {}:{} on the requested resource",
                    requirement.adapter, requirement.operation
                ));
            }
        }

        let outcome = if reasons.is_empty() {
            if effect.risk >= self.config.approval_threshold
                || effect.reversibility != Reversibility::Reversible
            {
                PolicyOutcome::RequireApproval
            } else {
                PolicyOutcome::Allow
            }
        } else {
            matched.clear();
            PolicyOutcome::Deny
        };

        PolicyDecision {
            id: PolicyDecisionId::new(),
            effect_id: effect.id,
            outcome,
            reasons,
            capability_ids: matched,
            effect_digest: digest,
            decided_at: now,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn capability_covers(
        capability: &Capability,
        effect: &Effect,
        transaction_id: TransactionId,
        intent_id: veyra_protocol::IntentId,
        status: CapabilityStatus,
        requested_constraints: &BTreeMap<String, String>,
        now: DateTime<Utc>,
    ) -> bool {
        !status.revoked
            && status.uses < capability.max_uses
            && !capability.nonce.trim().is_empty()
            && capability.principal_id == effect.principal_id
            && capability.intent_id.is_none_or(|bound| bound == intent_id)
            && capability
                .transaction_id
                .is_none_or(|bound| bound == transaction_id)
            && capability.adapter == effect.adapter
            && capability
                .operations
                .iter()
                .any(|operation| operation == &effect.operation)
            && now >= capability.not_before
            && now < capability.expires_at
            && capability.max_uses > 0
            && capability
                .resources
                .iter()
                .any(|scope| resource_covers(scope, &effect.resource))
            && constraints_cover(capability, effect, requested_constraints)
    }

    /// Build a short-lived approval challenge for the exact preflighted effect.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Digest`] if the effect cannot be canonically serialized, or
    /// [`PolicyError::InvalidApprovalRequest`] for a pending preview.
    pub fn approval_request(
        &self,
        transaction_id: TransactionId,
        effect: &Effect,
        now: DateTime<Utc>,
        lifetime: Duration,
    ) -> Result<ApprovalRequest, PolicyError> {
        if lifetime <= Duration::zero() || lifetime > self.config.maximum_approval_lifetime {
            return Err(PolicyError::InvalidLifetime);
        }
        if matches!(effect.preview, veyra_protocol::Preview::Pending) {
            return Err(PolicyError::InvalidApprovalRequest);
        }
        Ok(ApprovalRequest {
            id: ApprovalRequestId::new(),
            transaction_id,
            effect_id: effect.id,
            effect_digest: effect.content_digest().map_err(PolicyError::Digest)?,
            risk: effect.risk,
            resource: effect.resource.clone(),
            preview: effect.preview.clone(),
            nonce: ApprovalRequestId::new().to_string(),
            created_at: now,
            expires_at: now + lifetime,
        })
    }

    /// Validate a grant against its challenge and the effect immediately before staging.
    ///
    /// # Errors
    ///
    /// Returns a typed error for expiration, replay, mismatched bindings, or mutation.
    pub fn verify_approval(
        &self,
        request: &ApprovalRequest,
        grant: &ApprovalGrant,
        effect: &Effect,
        transaction_id: TransactionId,
        consumed_nonces: &HashSet<String>,
        now: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        if request.transaction_id != transaction_id
            || grant.transaction_id != transaction_id
            || request.effect_id != effect.id
            || grant.request_id != request.id
        {
            return Err(PolicyError::BindingMismatch);
        }
        if request.nonce.is_empty()
            || request.nonce.len() > 256
            || now < request.created_at
            || now >= request.expires_at
            || now >= grant.expires_at
            || grant.granted_at < request.created_at
            || grant.granted_at > now
            || grant.expires_at <= grant.granted_at
            || grant.expires_at > request.expires_at
        {
            return Err(PolicyError::ExpiredApproval);
        }
        if consumed_nonces.contains(&grant.nonce) {
            return Err(PolicyError::ApprovalReplay);
        }
        if request
            .nonce
            .as_bytes()
            .ct_eq(grant.nonce.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(PolicyError::BindingMismatch);
        }
        let current = effect.content_digest().map_err(PolicyError::Digest)?;
        if current
            .as_bytes()
            .ct_eq(request.effect_digest.as_bytes())
            .unwrap_u8()
            != 1
            || current
                .as_bytes()
                .ct_eq(grant.effect_digest.as_bytes())
                .unwrap_u8()
                != 1
        {
            return Err(PolicyError::EffectMutated);
        }
        Ok(())
    }

    /// Create the grant corresponding to an approval challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidLifetime`] for a non-positive or overlong lifetime.
    pub fn grant(
        request: &ApprovalRequest,
        approver_id: veyra_protocol::PrincipalId,
        now: DateTime<Utc>,
        lifetime: Duration,
    ) -> Result<ApprovalGrant, PolicyError> {
        if lifetime <= Duration::zero() || now + lifetime > request.expires_at {
            return Err(PolicyError::InvalidLifetime);
        }
        Ok(ApprovalGrant {
            id: ApprovalGrantId::new(),
            request_id: request.id,
            transaction_id: request.transaction_id,
            approver_id,
            effect_digest: request.effect_digest.clone(),
            nonce: request.nonce.clone(),
            granted_at: now,
            expires_at: now + lifetime,
        })
    }
}

fn constraints_cover(
    capability: &Capability,
    effect: &Effect,
    requested: &BTreeMap<String, String>,
) -> bool {
    const KNOWN_CONSTRAINTS: [&str; 3] = ["max_timeout_ms", "max_risk", "allow_irreversible"];
    if capability.constraints.iter().any(|(name, value)| {
        !KNOWN_CONSTRAINTS.contains(&name.as_str()) && requested.get(name) != Some(value)
    }) {
        return false;
    }
    if !requested.iter().all(|(name, value)| {
        capability
            .constraints
            .get(name)
            .is_some_and(|allowed| allowed == value)
    }) {
        return false;
    }
    if let Some(value) = capability.constraints.get("max_timeout_ms") {
        let Ok(limit) = value.parse::<u64>() else {
            return false;
        };
        if effect.timeout_ms > limit {
            return false;
        }
    }
    if effect.reversibility == Reversibility::Irreversible
        && capability
            .constraints
            .get("allow_irreversible")
            .map(String::as_str)
            != Some("true")
    {
        return false;
    }
    if let Some(maximum) = capability.constraints.get("max_risk")
        && parse_risk(maximum).is_none_or(|risk| effect.risk > risk)
    {
        return false;
    }
    true
}

fn parse_risk(value: &str) -> Option<RiskLevel> {
    match value {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        "critical" => Some(RiskLevel::Critical),
        _ => None,
    }
}

/// Return whether an authorized resource envelope contains a requested resource.
pub fn resource_covers(granted: &ResourceScope, requested: &ResourceScope) -> bool {
    match (granted, requested) {
        (
            ResourceScope::Filesystem {
                workspace: granted_workspace,
                path: granted_path,
            },
            ResourceScope::Filesystem {
                workspace: requested_workspace,
                path: requested_path,
            },
        ) => filesystem_path_covers(
            granted_workspace,
            granted_path,
            requested_workspace,
            requested_path,
        ),
        (
            ResourceScope::Filesystem {
                workspace: granted_workspace,
                path: granted_path,
            },
            ResourceScope::FilesystemSet {
                workspace: requested_workspace,
                paths: requested_paths,
            },
        ) => {
            !requested_paths.is_empty()
                && requested_paths.iter().all(|requested_path| {
                    filesystem_path_covers(
                        granted_workspace,
                        granted_path,
                        requested_workspace,
                        requested_path,
                    )
                })
        }
        (
            ResourceScope::FilesystemSet {
                workspace: granted_workspace,
                paths: granted_paths,
            },
            ResourceScope::FilesystemSet {
                workspace: requested_workspace,
                paths: requested_paths,
            },
        ) => filesystem_set_covers(
            granted_workspace,
            granted_paths,
            requested_workspace,
            requested_paths,
        ),
        (
            ResourceScope::FilesystemSet {
                workspace: granted_workspace,
                paths: granted_paths,
            },
            ResourceScope::Filesystem {
                workspace: requested_workspace,
                path: requested_path,
            },
        ) => filesystem_set_covers(
            granted_workspace,
            granted_paths,
            requested_workspace,
            std::slice::from_ref(requested_path),
        ),
        _ => other_resource_covers(granted, requested),
    }
}

fn other_resource_covers(granted: &ResourceScope, requested: &ResourceScope) -> bool {
    match (granted, requested) {
        (
            ResourceScope::Http {
                scheme: granted_scheme,
                domain: granted_domain,
                port: granted_port,
                path_prefix: granted_path,
            },
            ResourceScope::Http {
                scheme: requested_scheme,
                domain: requested_domain,
                port: requested_port,
                path_prefix: requested_path,
            },
        ) => {
            granted_scheme.eq_ignore_ascii_case(requested_scheme)
                && granted_domain.eq_ignore_ascii_case(requested_domain)
                && granted_port == requested_port
                && http_path_covers(granted_path, requested_path)
        }
        (
            ResourceScope::Process {
                executable: granted_executable,
                workdir: granted_workdir,
            },
            ResourceScope::Process {
                executable: requested_executable,
                workdir: requested_workdir,
            },
        ) => granted_executable == requested_executable && granted_workdir == requested_workdir,
        (
            ResourceScope::Generic {
                namespace: granted_namespace,
                resource: granted_resource,
            },
            ResourceScope::Generic {
                namespace: requested_namespace,
                resource: requested_resource,
            },
        ) => granted_namespace == requested_namespace && granted_resource == requested_resource,
        _ => false,
    }
}

fn filesystem_path_covers(
    granted_workspace: &str,
    granted_path: &str,
    requested_workspace: &str,
    requested_path: &str,
) -> bool {
    granted_workspace == requested_workspace
        && clean_relative(granted_path).is_some_and(|granted_parts| {
            clean_relative(requested_path).is_some_and(|requested_parts| {
                granted_parts.len() <= requested_parts.len()
                    && granted_parts
                        .iter()
                        .zip(requested_parts.iter())
                        .all(|(left, right)| left == right)
            })
        })
}

fn filesystem_set_covers(
    granted_workspace: &str,
    granted_paths: &[String],
    requested_workspace: &str,
    requested_paths: &[String],
) -> bool {
    !granted_paths.is_empty()
        && !requested_paths.is_empty()
        && requested_paths.iter().all(|requested_path| {
            granted_paths.iter().any(|granted_path| {
                filesystem_path_covers(
                    granted_workspace,
                    granted_path,
                    requested_workspace,
                    requested_path,
                )
            })
        })
}

fn clean_relative(path: &str) -> Option<Vec<&str>> {
    if path == "." {
        return Some(Vec::new());
    }
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return None;
    }
    Some(parts)
}

fn http_path_covers(granted: &str, requested: &str) -> bool {
    if !granted.starts_with('/') || !requested.starts_with('/') || requested.contains("..") {
        return false;
    }
    granted == "/"
        || granted == requested
        || requested
            .strip_prefix(granted.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Approval construction or verification failure.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Canonical effect serialization failed.
    #[error("could not digest effect: {0}")]
    Digest(#[source] veyra_protocol::CanonicalError),
    /// Request and grant bindings do not match.
    #[error("approval binding does not match the request, transaction, or effect")]
    BindingMismatch,
    /// The approval request or grant has expired.
    #[error("approval is expired or predates its request")]
    ExpiredApproval,
    /// The exact approval nonce was already consumed.
    #[error("approval nonce was already consumed")]
    ApprovalReplay,
    /// The approved effect differs from the effect about to execute.
    #[error("effect content changed after approval")]
    EffectMutated,
    /// Approval lifetime is zero, negative, or exceeds its challenge.
    #[error("approval lifetime is invalid")]
    InvalidLifetime,
    /// Approval cannot be constructed before an authoritative adapter preview exists.
    #[error("approval request has no authoritative preview")]
    InvalidApprovalRequest,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use serde_json::json;
    use veyra_protocol::{
        CapabilityRequirement, CausalParent, EffectId, IntentId, PROTOCOL_VERSION, PlanId, Preview,
        PrincipalId, RetryPolicy, StepId, public,
    };

    use super::*;

    fn effect() -> Effect {
        let resource = ResourceScope::Filesystem {
            workspace: "demo".into(),
            path: "notes/hello.txt".into(),
        };
        Effect {
            schema_version: PROTOCOL_VERSION.into(),
            id: EffectId::new(),
            causal_parent: CausalParent {
                intent_id: IntentId::new(),
                plan_id: PlanId::new(),
                step_id: StepId::new(),
                effect_id: None,
            },
            principal_id: PrincipalId::new(),
            adapter: "filesystem".into(),
            operation: "create".into(),
            inputs: BTreeMap::from([("content".into(), public("hello"))]),
            resource: resource.clone(),
            preconditions: vec![],
            expected_postconditions: vec![],
            risk: RiskLevel::Medium,
            reversibility: Reversibility::Reversible,
            preview: Preview::Filesystem {
                operation: "create".into(),
                path: "notes/hello.txt".into(),
                before_sha256: None,
                after_sha256: Some("aa".repeat(32)),
                unified_diff: Some("+hello".into()),
            },
            idempotency_key: "create-hello-v1".into(),
            timeout_ms: 1_000,
            retry: RetryPolicy {
                max_attempts: 1,
                backoff_ms: 0,
                retryable_errors: vec![],
            },
            required_capabilities: vec![CapabilityRequirement {
                adapter: "filesystem".into(),
                operation: "create".into(),
                resource,
                constraints: BTreeMap::new(),
            }],
            inverse: None,
        }
    }

    fn capability(effect: &Effect, tx: TransactionId, now: DateTime<Utc>) -> Capability {
        Capability {
            id: CapabilityId::new(),
            principal_id: effect.principal_id,
            intent_id: Some(effect.causal_parent.intent_id),
            transaction_id: Some(tx),
            adapter: effect.adapter.clone(),
            operations: vec![effect.operation.clone()],
            resources: vec![ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: "notes".into(),
            }],
            constraints: BTreeMap::from([
                ("max_timeout_ms".into(), "2000".into()),
                ("max_risk".into(), "medium".into()),
            ]),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::minutes(5),
            nonce: "unique-capability".into(),
            max_uses: 1,
            issued_at: now,
        }
    }

    #[test]
    fn deny_by_default_and_allow_with_exact_live_capability() {
        let now = Utc::now();
        let effect = effect();
        let tx = TransactionId::new();
        let engine = PolicyEngine::new(PolicyConfig::default());
        let denied = engine.evaluate(
            &effect,
            tx,
            effect.causal_parent.intent_id,
            &[],
            &HashMap::new(),
            now,
        );
        assert_eq!(denied.outcome, PolicyOutcome::Deny);

        let grant = capability(&effect, tx, now);
        let missing_status = engine.evaluate(
            &effect,
            tx,
            effect.causal_parent.intent_id,
            std::slice::from_ref(&grant),
            &HashMap::new(),
            now,
        );
        assert_eq!(missing_status.outcome, PolicyOutcome::Deny);
        let allowed = engine.evaluate(
            &effect,
            tx,
            effect.causal_parent.intent_id,
            std::slice::from_ref(&grant),
            &HashMap::from([(grant.id, CapabilityStatus::default())]),
            now,
        );
        assert_eq!(allowed.outcome, PolicyOutcome::RequireApproval);
    }

    #[test]
    fn unsupported_retries_and_unenforceable_constraints_are_denied() {
        let now = Utc::now();
        let tx = TransactionId::new();
        let engine = PolicyEngine::new(PolicyConfig::default());
        let mut candidate = effect();
        let mut grant = capability(&candidate, tx, now);

        candidate.retry.max_attempts = 2;
        assert_eq!(
            engine
                .evaluate(
                    &candidate,
                    tx,
                    candidate.causal_parent.intent_id,
                    &[grant.clone()],
                    &HashMap::from([(grant.id, CapabilityStatus::default())]),
                    now,
                )
                .outcome,
            PolicyOutcome::Deny
        );

        candidate.retry.max_attempts = 1;
        grant.constraints.insert("region".into(), "us-east".into());
        assert_eq!(
            engine
                .evaluate(
                    &candidate,
                    tx,
                    candidate.causal_parent.intent_id,
                    &[grant.clone()],
                    &HashMap::from([(grant.id, CapabilityStatus::default())]),
                    now,
                )
                .outcome,
            PolicyOutcome::Deny
        );

        grant.constraints.remove("region");
        grant
            .constraints
            .insert("max_timeout_ms".into(), "not-a-number".into());
        assert_eq!(
            engine
                .evaluate(
                    &candidate,
                    tx,
                    candidate.causal_parent.intent_id,
                    std::slice::from_ref(&grant),
                    &HashMap::from([(grant.id, CapabilityStatus::default())]),
                    now,
                )
                .outcome,
            PolicyOutcome::Deny
        );
    }

    #[test]
    fn approval_rejects_mutated_effect_and_replay() {
        let now = Utc::now();
        let engine = PolicyEngine::new(PolicyConfig::default());
        let tx = TransactionId::new();
        let original = effect();
        let request = engine
            .approval_request(tx, &original, now, Duration::minutes(5))
            .unwrap();
        let grant = PolicyEngine::grant(
            &request,
            PrincipalId::new(),
            now + Duration::seconds(1),
            Duration::minutes(1),
        )
        .unwrap();
        let verification_time = now + Duration::seconds(1);
        engine
            .verify_approval(
                &request,
                &grant,
                &original,
                tx,
                &HashSet::new(),
                verification_time,
            )
            .unwrap();

        let mut mutated = original.clone();
        mutated.inputs.insert("content".into(), public("changed"));
        assert!(matches!(
            engine.verify_approval(
                &request,
                &grant,
                &mutated,
                tx,
                &HashSet::new(),
                verification_time
            ),
            Err(PolicyError::EffectMutated)
        ));
        assert!(matches!(
            engine.verify_approval(
                &request,
                &grant,
                &original,
                tx,
                &HashSet::from([grant.nonce.clone()]),
                verification_time
            ),
            Err(PolicyError::ApprovalReplay)
        ));
    }

    #[test]
    fn path_prefix_is_component_aware() {
        let granted = ResourceScope::Filesystem {
            workspace: "demo".into(),
            path: "safe".into(),
        };
        assert!(resource_covers(
            &granted,
            &ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: "safe/file.txt".into()
            }
        ));
        assert!(!resource_covers(
            &granted,
            &ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: "safe-escape/file.txt".into()
            }
        ));
    }

    proptest! {
        #[test]
        fn traversal_never_falls_under_workspace(segment in "[a-zA-Z0-9._-]{0,32}") {
            let requested = ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: format!("safe/../{segment}"),
            };
            let granted = ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: ".".into(),
            };
            prop_assert!(!resource_covers(&granted, &requested));
        }

        #[test]
        fn any_effect_mutation_invalidates_approval(suffix in ".{1,24}") {
            let now = Utc::now();
            let engine = PolicyEngine::new(PolicyConfig::default());
            let tx = TransactionId::new();
            let original = effect();
            let request = engine.approval_request(tx, &original, now, Duration::minutes(5)).unwrap();
            let grant = PolicyEngine::grant(
                &request,
                PrincipalId::new(),
                now,
                Duration::minutes(1),
            ).unwrap();
            let mut mutated = original.clone();
            mutated.inputs.insert("content".into(), public(json!(format!("changed:{suffix}"))));
            let rejected = matches!(
                engine.verify_approval(&request, &grant, &mutated, tx, &HashSet::new(), now),
                Err(PolicyError::EffectMutated)
            );
            prop_assert!(rejected);
        }
    }
}
