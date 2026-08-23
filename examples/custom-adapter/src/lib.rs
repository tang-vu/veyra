//! Minimal out-of-tree adapter: a reversible, non-persistent in-memory counter.
//!
//! The example demonstrates the complete contributor contract. It is intentionally not suitable
//! for durable production state because its counter map does not survive process restart.

use std::{collections::BTreeMap, sync::Mutex};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use veyra_executor::{
    AdapterContext, AdapterError, AdapterPreflight, AdapterRecovery, AdapterResult, EffectAdapter,
    StagedEffect, validate_capability_constraints,
};
use veyra_protocol::{
    Condition, Effect, InputValue, Preview, ResourceScope, Reversibility, RiskLevel,
    VerificationCheck,
};

const MAXIMUM_COUNTER_NAME_BYTES: usize = 128;
const MAXIMUM_INCREMENT_MAGNITUDE: i64 = 1_000_000;

/// Educational reversible counter adapter.
#[derive(Debug, Default)]
pub struct CounterAdapter {
    counters: Mutex<BTreeMap<String, i64>>,
}

#[async_trait]
impl EffectAdapter for CounterAdapter {
    fn name(&self) -> &'static str {
        "example.counter"
    }

    fn validate(&self, effect: &Effect) -> Result<(), AdapterError> {
        if effect.adapter != self.name()
            || effect.operation != "increment"
            || effect.reversibility != Reversibility::Reversible
            || effect.risk < RiskLevel::Medium
        {
            return Err(AdapterError::InvalidEffect(
                "counter effects require example.counter/increment, reversible classification, and at least medium risk"
                    .into(),
            ));
        }
        let counter = counter_name(effect)?;
        if effect.inputs.len() != 1 || !effect.inputs.contains_key("amount") {
            return Err(AdapterError::InvalidEffect(
                "counter effect requires exactly one `amount` input".into(),
            ));
        }
        let _ = amount(effect)?;
        validate_capability_constraints(effect, &[])?;
        if !effect.preconditions.is_empty() {
            return Err(AdapterError::InvalidEffect(
                "counter preconditions are not implemented and cannot be declared".into(),
            ));
        }
        if effect.expected_postconditions.is_empty()
            || effect.expected_postconditions.iter().any(|condition| {
                !matches!(condition, Condition::Custom { name, parameters }
                    if name == "example.counter_equals/v1"
                        && parameters.as_object().is_some_and(|parameters|
                            parameters.len() == 2
                                && parameters.get("counter").and_then(Value::as_str) == Some(counter)
                                && parameters.get("expected").and_then(Value::as_i64).is_some()))
            })
        {
            return Err(AdapterError::InvalidEffect(
                "counter effect declares an unsupported or malformed postcondition".into(),
            ));
        }
        Ok(())
    }

    async fn preflight(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<AdapterPreflight, AdapterError> {
        self.validate(effect)?;
        let counter = counter_name(effect)?;
        let before = self.value(counter)?;
        let after = before
            .checked_add(amount(effect)?)
            .ok_or_else(|| AdapterError::Precondition("counter increment would overflow".into()))?;
        Ok(AdapterPreflight {
            preview: counter_preview(counter, before, after),
            observations: json!({"counter": counter, "before": before, "after": after}),
        })
    }

    async fn stage(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<StagedEffect, AdapterError> {
        self.validate(effect)?;
        let counter = counter_name(effect)?;
        let before = self.value(counter)?;
        let after = before
            .checked_add(amount(effect)?)
            .ok_or_else(|| AdapterError::Precondition("counter increment would overflow".into()))?;
        if effect.preview != counter_preview(counter, before, after) {
            return Err(AdapterError::Toctou(
                "counter changed after its approved preview".into(),
            ));
        }
        Ok(StagedEffect {
            adapter: self.name().into(),
            effect_id: effect.id,
            effect_digest: effect.content_digest().map_err(AdapterError::Canonical)?,
            data: json!({"counter": counter, "before": before, "after": after}),
            staged_at: Utc::now(),
        })
    }

    async fn execute(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        self.validate(effect)?;
        validate_stage(self.name(), effect, staged)?;
        let (counter, before, after) = stage_values(staged)?;
        let mut counters = self.lock()?;
        if counters.get(counter).copied().unwrap_or_default() != before {
            return Err(AdapterError::Toctou("counter changed after staging".into()));
        }
        counters.insert(counter.into(), after);
        Ok(AdapterResult {
            outcome: "incremented".into(),
            data: json!({"counter": counter, "value": after}),
            post_state_digest: None,
        })
    }

    async fn verify(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _result: &AdapterResult,
        _context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError> {
        self.validate(effect)?;
        validate_stage(self.name(), effect, staged)?;
        let (counter, _before, after) = stage_values(staged)?;
        let observed = self.value(counter)?;
        Ok(vec![VerificationCheck {
            condition: Condition::Custom {
                name: "example.counter_equals/v1".into(),
                parameters: json!({"counter": counter, "expected": after}),
            },
            passed: observed == after,
            message: format!("counter `{counter}` observed value {observed}"),
        }])
    }

    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError> {
        self.validate(effect)?;
        validate_stage(self.name(), effect, staged)?;
        let (counter, before, after) = stage_values(staged)?;
        let mut counters = self.lock()?;
        if counters.get(counter).copied().unwrap_or_default() != after {
            return Ok(AdapterRecovery {
                restored: false,
                details: json!({"reason": "counter changed after execution; refusing to clobber"}),
            });
        }
        counters.insert(counter.into(), before);
        Ok(AdapterRecovery {
            restored: true,
            details: json!({"counter": counter, "restored_value": before}),
        })
    }
}

impl CounterAdapter {
    fn value(&self, counter: &str) -> Result<i64, AdapterError> {
        Ok(self.lock()?.get(counter).copied().unwrap_or_default())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, i64>>, AdapterError> {
        self.counters
            .lock()
            .map_err(|_| AdapterError::InvalidStage("counter mutex was poisoned".into()))
    }
}

fn counter_name(effect: &Effect) -> Result<&str, AdapterError> {
    match &effect.resource {
        ResourceScope::Generic {
            namespace,
            resource,
        } if namespace == "example.counter"
            && !resource.is_empty()
            && resource.len() <= MAXIMUM_COUNTER_NAME_BYTES
            && resource
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) =>
        {
            Ok(resource)
        }
        _ => Err(AdapterError::InvalidEffect(
            "counter resource must use the example.counter generic namespace".into(),
        )),
    }
}

fn amount(effect: &Effect) -> Result<i64, AdapterError> {
    match effect.inputs.get("amount") {
        Some(InputValue::Public { value }) => value
            .as_i64()
            .filter(|amount| {
                *amount != 0 && amount.unsigned_abs() <= MAXIMUM_INCREMENT_MAGNITUDE as u64
            })
            .ok_or_else(|| {
                AdapterError::InvalidEffect(
                    "counter amount must be a non-zero bounded public integer".into(),
                )
            }),
        _ => Err(AdapterError::InvalidEffect(
            "counter amount must be a public integer".into(),
        )),
    }
}

fn counter_preview(counter: &str, before: i64, after: i64) -> Preview {
    Preview::Custom {
        media_type: "application/vnd.veyra.example-counter+json;v=1".into(),
        value: json!({"counter": counter, "before": before, "after": after}),
    }
}

fn validate_stage(
    adapter_name: &str,
    effect: &Effect,
    staged: &StagedEffect,
) -> Result<(), AdapterError> {
    let digest = effect.content_digest().map_err(AdapterError::Canonical)?;
    if staged.adapter != adapter_name
        || staged.effect_id != effect.id
        || staged.effect_digest != digest
    {
        return Err(AdapterError::Toctou(
            "stage is not bound to the exact effect".into(),
        ));
    }
    Ok(())
}

fn stage_values(staged: &StagedEffect) -> Result<(&str, i64, i64), AdapterError> {
    let field = |key| {
        staged
            .data
            .get(key)
            .and_then(Value::as_i64)
            .ok_or_else(|| AdapterError::InvalidStage("counter stage is malformed".into()))
    };
    let counter = staged
        .data
        .get("counter")
        .and_then(Value::as_str)
        .ok_or_else(|| AdapterError::InvalidStage("counter stage is malformed".into()))?;
    Ok((counter, field("before")?, field("after")?))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use veyra_executor::DenySecretResolver;
    use veyra_protocol::{
        CapabilityRequirement, CausalParent, EffectId, IntentId, PROTOCOL_VERSION, PlanId,
        PrincipalId, RetryPolicy, RiskLevel, StepId, TransactionId,
    };

    use super::*;

    #[tokio::test]
    async fn complete_contributor_contract_is_non_clobbering_and_reversible() {
        let adapter = CounterAdapter::default();
        let context = AdapterContext {
            transaction_id: TransactionId::new(),
            secrets: Arc::new(DenySecretResolver),
        };
        let resource = ResourceScope::Generic {
            namespace: "example.counter".into(),
            resource: "requests".into(),
        };
        let mut effect = Effect {
            schema_version: PROTOCOL_VERSION.into(),
            id: EffectId::new(),
            causal_parent: CausalParent {
                intent_id: IntentId::new(),
                plan_id: PlanId::new(),
                step_id: StepId::new(),
                effect_id: None,
            },
            principal_id: PrincipalId::new(),
            adapter: adapter.name().into(),
            operation: "increment".into(),
            inputs: BTreeMap::from([("amount".into(), InputValue::Public { value: json!(3) })]),
            resource: resource.clone(),
            preconditions: vec![],
            expected_postconditions: vec![Condition::Custom {
                name: "example.counter_equals/v1".into(),
                parameters: json!({"counter": "requests", "expected": 3}),
            }],
            risk: RiskLevel::Medium,
            reversibility: Reversibility::Reversible,
            preview: Preview::Pending,
            idempotency_key: "counter-test-1".into(),
            timeout_ms: 1_000,
            retry: RetryPolicy {
                max_attempts: 1,
                backoff_ms: 0,
                retryable_errors: vec![],
            },
            required_capabilities: vec![CapabilityRequirement {
                adapter: adapter.name().into(),
                operation: "increment".into(),
                resource,
                constraints: BTreeMap::new(),
            }],
            inverse: None,
        };
        effect.preview = adapter.preflight(&effect, &context).await.unwrap().preview;
        let staged = adapter.stage(&effect, &context).await.unwrap();
        let result = adapter.execute(&effect, &staged, &context).await.unwrap();
        assert!(
            adapter
                .verify(&effect, &staged, &result, &context)
                .await
                .unwrap()
                .iter()
                .all(|check| check.passed)
        );
        assert!(
            adapter
                .rollback(&effect, &staged, &context)
                .await
                .unwrap()
                .restored
        );
        assert_eq!(adapter.value("requests").unwrap(), 0);

        let mut unsupported_input = effect.clone();
        unsupported_input.inputs.insert(
            "ignored".into(),
            InputValue::Public {
                value: json!("misleading"),
            },
        );
        assert!(matches!(
            adapter.validate(&unsupported_input),
            Err(AdapterError::InvalidEffect(_))
        ));

        let mut unsupported_constraint = effect.clone();
        unsupported_constraint.required_capabilities[0]
            .constraints
            .insert("max_increment".into(), "1".into());
        assert!(matches!(
            adapter.validate(&unsupported_constraint),
            Err(AdapterError::InvalidEffect(_))
        ));

        effect.risk = RiskLevel::Low;
        assert!(matches!(
            adapter.validate(&effect),
            Err(AdapterError::InvalidEffect(_))
        ));
    }
}
