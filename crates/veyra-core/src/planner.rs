//! Model-independent planner boundary and deterministic/offline implementations.

use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use reqwest::{Url, header::HeaderValue};
use schemars::schema_for;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use veyra_executor::SecretValue;
use veyra_protocol::{
    CapabilityRequirement, CausalParent, Condition, Effect, EffectId, Intent, PROTOCOL_VERSION,
    Plan, PlanId, Preview, ResourceScope, RetryPolicy, Reversibility, RiskLevel, Step, StepId,
    public,
};

/// A source of proposed effects. Planners have no capability or execution authority.
#[async_trait]
pub trait Planner: Send + Sync {
    /// Stable planner implementation name stored in plans and audit events.
    fn name(&self) -> &'static str;

    /// Propose a plan within the intent's requested resource envelope.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`] for malformed fixture context, unavailable provider credentials,
    /// provider failure, or strict plan deserialization failure.
    async fn plan(&self, intent: &Intent) -> Result<Plan, PlannerError>;
}

/// Offline planner for tests and the deterministic demo.
#[derive(Clone, Debug, Default)]
pub struct FixturePlanner;

#[async_trait]
impl Planner for FixturePlanner {
    fn name(&self) -> &'static str {
        "fixture/v1"
    }

    async fn plan(&self, intent: &Intent) -> Result<Plan, PlannerError> {
        fixture_plan(intent, self.name())
    }
}

#[derive(Debug)]
struct FixtureFields {
    operation: String,
    path: String,
    workspace: String,
    destination: Option<String>,
}

fn fixture_plan(intent: &Intent, planner: &str) -> Result<Plan, PlannerError> {
    let fields = FixtureFields {
        operation: context_string(intent, "operation")?,
        path: context_string(intent, "path")?,
        workspace: context_string(intent, "workspace")?,
        destination: intent
            .context
            .get("destination")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    let plan_id = PlanId::new();
    let step_id = StepId::new();
    let effect = fixture_effect(intent, plan_id, step_id, &fields)?;
    Ok(Plan {
        schema_version: PROTOCOL_VERSION.into(),
        id: plan_id,
        intent_id: intent.id,
        planner: planner.into(),
        steps: vec![Step {
            id: step_id,
            summary: format!(
                "{} `{}` in workspace `{}`",
                fields.operation, fields.path, fields.workspace
            ),
            effects: vec![effect],
        }],
        created_at: intent.created_at,
    })
}

fn fixture_effect(
    intent: &Intent,
    plan_id: PlanId,
    step_id: StepId,
    fields: &FixtureFields,
) -> Result<Effect, PlannerError> {
    let resource = fixture_resource(fields)?;
    let mut inputs = BTreeMap::new();
    if matches!(fields.operation.as_str(), "create" | "patch") {
        inputs.insert("content".into(), public(context_string(intent, "content")?));
    }
    Ok(Effect {
        schema_version: PROTOCOL_VERSION.into(),
        id: EffectId::new(),
        causal_parent: CausalParent {
            intent_id: intent.id,
            plan_id,
            step_id,
            effect_id: None,
        },
        principal_id: intent.principal_id,
        adapter: "filesystem".into(),
        operation: fields.operation.clone(),
        inputs,
        resource: resource.clone(),
        preconditions: vec![],
        expected_postconditions: fixture_postconditions(intent, fields)?,
        risk: if fields.operation == "read" {
            RiskLevel::Low
        } else {
            RiskLevel::Medium
        },
        reversibility: Reversibility::Reversible,
        preview: Preview::Pending,
        idempotency_key: format!("fixture:{}:{}:{}", intent.id, fields.operation, fields.path),
        timeout_ms: 5_000,
        retry: RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
            retryable_errors: vec![],
        },
        required_capabilities: vec![CapabilityRequirement {
            adapter: "filesystem".into(),
            operation: fields.operation.clone(),
            resource,
            constraints: BTreeMap::new(),
        }],
        inverse: None,
    })
}

fn fixture_resource(fields: &FixtureFields) -> Result<ResourceScope, PlannerError> {
    if fields.operation == "move" {
        Ok(ResourceScope::FilesystemSet {
            workspace: fields.workspace.clone(),
            paths: vec![fields.path.clone(), fixture_destination(fields)?.to_owned()],
        })
    } else {
        Ok(ResourceScope::Filesystem {
            workspace: fields.workspace.clone(),
            path: fields.path.clone(),
        })
    }
}

fn fixture_postconditions(
    intent: &Intent,
    fields: &FixtureFields,
) -> Result<Vec<Condition>, PlannerError> {
    match fields.operation.as_str() {
        "create" | "patch" => {
            let content = context_string(intent, "content")?;
            Ok(vec![Condition::FileSha256 {
                path: fields.path.clone(),
                digest: sha256(content.as_bytes()),
            }])
        }
        "delete" => Ok(vec![Condition::FileExists {
            path: fields.path.clone(),
            expected: false,
        }]),
        "move" => Ok(vec![
            Condition::FileExists {
                path: fields.path.clone(),
                expected: false,
            },
            Condition::FileExists {
                path: fixture_destination(fields)?.to_owned(),
                expected: true,
            },
        ]),
        "read" => Ok(vec![Condition::FileExists {
            path: fields.path.clone(),
            expected: true,
        }]),
        operation => Err(PlannerError::Fixture(format!(
            "fixture operation `{operation}` is not supported"
        ))),
    }
}

fn fixture_destination(fields: &FixtureFields) -> Result<&str, PlannerError> {
    fields
        .destination
        .as_deref()
        .ok_or_else(|| PlannerError::Fixture("move requires `destination` context".into()))
}

/// Configuration for a Responses-API compatible planner endpoint.
#[derive(Clone, Debug)]
pub struct OpenAiPlannerConfig {
    /// Full Responses endpoint URL, normally `https://api.openai.com/v1/responses`.
    pub endpoint: Url,
    /// Provider model identifier.
    pub model: String,
    /// Environment variable containing the API key. The value is never placed in model context.
    pub api_key_environment: String,
    /// Provider request timeout.
    pub timeout: Duration,
}

/// Planner using an `OpenAI` Responses-compatible endpoint with strict JSON Schema output.
#[derive(Clone, Debug)]
pub struct OpenAiCompatiblePlanner {
    config: OpenAiPlannerConfig,
    client: reqwest::Client,
}

impl OpenAiCompatiblePlanner {
    /// Construct a provider adapter without reading credentials or making a request.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`] if the endpoint is not HTTPS or the HTTP client cannot initialize.
    pub fn new(config: OpenAiPlannerConfig) -> Result<Self, PlannerError> {
        if config.endpoint.scheme() != "https" {
            return Err(PlannerError::Configuration(
                "model endpoint must use HTTPS".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(PlannerError::Provider)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Planner for OpenAiCompatiblePlanner {
    fn name(&self) -> &'static str {
        "openai-responses-compatible/v1"
    }

    async fn plan(&self, intent: &Intent) -> Result<Plan, PlannerError> {
        let raw_key = std::env::var(&self.config.api_key_environment).map_err(|_| {
            PlannerError::MissingCredential(self.config.api_key_environment.clone())
        })?;
        let api_key = SecretValue::new(raw_key.into_bytes());
        let authorization = HeaderValue::from_bytes(
            [b"Bearer ".as_slice(), api_key.expose()]
                .concat()
                .as_slice(),
        )
        .map_err(|_| PlannerError::Configuration("API key is not a valid header value".into()))?;
        let schema = serde_json::to_value(schema_for!(Plan)).map_err(PlannerError::Json)?;
        let request = json!({
            "model": self.config.model,
            "store": false,
            "instructions": "Propose effects only. Do not claim authority. Stay within requested_resources. Use secret references, never raw credentials. Return exactly the supplied Plan schema.",
            "input": serde_json::to_string(intent).map_err(PlannerError::Json)?,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "veyra_plan",
                    "strict": true,
                    "schema": schema
                }
            }
        });
        let response = self
            .client
            .post(self.config.endpoint.clone())
            .header("authorization", authorization)
            .json(&request)
            .send()
            .await
            .map_err(PlannerError::Provider)?;
        drop(api_key);
        let status = response.status();
        if !status.is_success() {
            return Err(PlannerError::ProviderStatus(status.as_u16()));
        }
        let response: Value = response.json().await.map_err(PlannerError::Provider)?;
        let text = response_text(&response).ok_or(PlannerError::MissingOutput)?;
        serde_json::from_str(text).map_err(PlannerError::Json)
    }
}

fn context_string(intent: &Intent, key: &str) -> Result<String, PlannerError> {
    intent
        .context
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| PlannerError::Fixture(format!("intent context requires string `{key}`")))
}

fn response_text(response: &Value) -> Option<&str> {
    response
        .get("output_text")
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("output")?
                .as_array()?
                .iter()
                .flat_map(|item| {
                    item.get("content")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .find(|content| content.get("type").and_then(Value::as_str) == Some("output_text"))?
                .get("text")?
                .as_str()
        })
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Planner failure with credential-safe normal display text.
#[derive(Debug, Error)]
pub enum PlannerError {
    /// Deterministic fixture context is incomplete or invalid.
    #[error("fixture planner input is invalid: {0}")]
    Fixture(String),
    /// Provider adapter configuration is invalid.
    #[error("planner provider configuration is invalid: {0}")]
    Configuration(String),
    /// Configured credential environment variable is absent. Its value is never included.
    #[error("planner credential environment variable `{0}` is not set")]
    MissingCredential(String),
    /// Provider network request or response decoding failed.
    #[error("planner provider request failed")]
    Provider(#[source] reqwest::Error),
    /// Provider returned a non-success status; its possibly sensitive body is not surfaced.
    #[error("planner provider returned HTTP status {0}")]
    ProviderStatus(u16),
    /// Provider response contains no structured output text.
    #[error("planner provider response contained no output text")]
    MissingOutput,
    /// Strict plan JSON serialization or deserialization failed.
    #[error("planner JSON did not match the Veyra plan schema")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use veyra_protocol::{IntentId, PrincipalId};

    use super::*;

    #[tokio::test]
    async fn fixture_planner_needs_no_key_and_stays_in_declared_shape() {
        let intent = Intent {
            schema_version: PROTOCOL_VERSION.into(),
            id: IntentId::new(),
            principal_id: PrincipalId::new(),
            summary: "create a greeting".into(),
            requested_resources: vec![ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: "notes".into(),
            }],
            context: BTreeMap::from([
                ("workspace".into(), json!("demo")),
                ("operation".into(), json!("create")),
                ("path".into(), json!("notes/hello.txt")),
                ("content".into(), json!("hello\n")),
            ]),
            created_at: Utc::now(),
        };
        let plan = FixturePlanner.plan(&intent).await.unwrap();
        assert_eq!(plan.planner, "fixture/v1");
        assert_eq!(plan.steps[0].effects[0].adapter, "filesystem");
        assert!(matches!(plan.steps[0].effects[0].preview, Preview::Pending));
    }

    #[test]
    fn response_output_text_extraction_does_not_assume_first_item() {
        let value = json!({
            "output": [
                {"type": "reasoning"},
                {"type": "message", "content": [
                    {"type": "refusal", "refusal": "no"},
                    {"type": "output_text", "text": "{\"schema_version\":\"v\"}"}
                ]}
            ]
        });
        assert_eq!(response_text(&value), Some("{\"schema_version\":\"v\"}"));
    }
}
