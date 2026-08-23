//! Extensible adapter boundary for staged, bounded side effects.

mod filesystem;
mod http;
mod process;
mod secret;
mod util;

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use veyra_protocol::{Effect, EffectId, Preview, TransactionId, VerificationCheck};

pub use filesystem::{FilesystemAdapter, FilesystemConfig};
pub use http::{HttpAdapter, HttpAdapterConfig, HttpRule};
pub use process::{ProcessAdapter, ProcessAdapterConfig, ProcessRule};
pub use secret::{DenySecretResolver, EnvironmentSecretResolver, SecretResolver, SecretValue};

/// Immutable context supplied by the trusted kernel to every adapter call.
#[derive(Clone)]
pub struct AdapterContext {
    /// Transaction containing the effect.
    pub transaction_id: TransactionId,
    /// Secret resolver available only at the adapter boundary.
    pub secrets: Arc<dyn SecretResolver>,
}

impl std::fmt::Debug for AdapterContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterContext")
            .field("transaction_id", &self.transaction_id)
            .field("secrets", &"[SECRET RESOLVER]")
            .finish()
    }
}

/// Result of side-effect-free adapter inspection.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPreflight {
    /// Structured preview that becomes part of the approved effect digest.
    pub preview: Preview,
    /// Redacted state observation used to explain the preview.
    pub observations: Value,
}

/// Durable, adapter-defined staging descriptor.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedEffect {
    /// Adapter that created the descriptor.
    pub adapter: String,
    /// Effect binding.
    pub effect_id: EffectId,
    /// Canonical effect digest at staging time.
    pub effect_digest: String,
    /// Adapter-private but secret-safe durable data.
    pub data: Value,
    /// Creation timestamp.
    pub staged_at: DateTime<Utc>,
}

/// Bounded, redacted adapter execution result.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResult {
    /// Stable adapter outcome code.
    pub outcome: String,
    /// Secret-safe result body.
    pub data: Value,
    /// Digest of the primary observed post-state or output.
    pub post_state_digest: Option<String>,
}

/// Result of rollback or best-effort compensation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRecovery {
    /// True only when the adapter verified restoration to its documented boundary.
    pub restored: bool,
    /// Secret-safe evidence or reason.
    pub details: Value,
}

/// Contributor-facing effect adapter contract.
///
/// Adapters inspect, stage, execute, verify, and recover effects, but never decide authority.
#[async_trait]
pub trait EffectAdapter: Send + Sync {
    /// Stable protocol adapter name.
    fn name(&self) -> &'static str;

    /// Validate adapter-specific effect shape without touching external state.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] for an unknown operation, malformed input, scope mismatch, or
    /// dishonest reversibility declaration.
    fn validate(&self, effect: &Effect) -> Result<(), AdapterError>;

    /// Inspect current state and build the exact preview to be approved.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when containment, policy, input, or precondition checks fail.
    async fn preflight(
        &self,
        effect: &Effect,
        context: &AdapterContext,
    ) -> Result<AdapterPreflight, AdapterError>;

    /// Prepare durable changes without applying the declared external side effect.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if preflight evidence changed or staging cannot be made durable.
    async fn stage(
        &self,
        effect: &Effect,
        context: &AdapterContext,
    ) -> Result<StagedEffect, AdapterError>;

    /// Cross the side-effect boundary exactly once for an idempotency reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] for changed preconditions, timeouts, limits, or execution failure.
    async fn execute(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError>;

    /// Check intrinsic adapter state and every declared postcondition.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when observations cannot be made safely. A failed condition is a
    /// successful return containing a check whose `passed` field is false.
    async fn verify(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        result: &AdapterResult,
        context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError>;

    /// Attempt rollback or compensation using durable staging evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when safe recovery cannot be attempted. Adapters must never
    /// overwrite state that changed after execution merely to report a successful rollback.
    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError>;
}

/// Registry that lets external adapters plug in without kernel source changes.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn EffectAdapter>>,
}

impl AdapterRegistry {
    /// Create an empty deny-by-default registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one adapter under its stable name.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::DuplicateAdapter`] if a name is already registered.
    pub fn register(&mut self, adapter: Arc<dyn EffectAdapter>) -> Result<(), AdapterError> {
        let name = adapter.name().to_owned();
        if self.adapters.insert(name.clone(), adapter).is_some() {
            return Err(AdapterError::DuplicateAdapter(name));
        }
        Ok(())
    }

    /// Resolve an explicitly registered adapter.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::AdapterDisabled`] for absent names.
    pub fn get(&self, name: &str) -> Result<Arc<dyn EffectAdapter>, AdapterError> {
        self.adapters
            .get(name)
            .cloned()
            .ok_or_else(|| AdapterError::AdapterDisabled(name.to_owned()))
    }

    /// Sorted registered adapter names for diagnostics and schema validation.
    pub fn names(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }
}

/// Safe adapter error taxonomy. Normal display text never embeds secret values or process output.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Adapter is absent or explicitly disabled.
    #[error("adapter `{0}` is not enabled")]
    AdapterDisabled(String),
    /// A second adapter attempted to claim an existing name.
    #[error("adapter `{0}` is already registered")]
    DuplicateAdapter(String),
    /// Operation is not part of the adapter contract.
    #[error("adapter `{adapter}` does not support operation `{operation}`")]
    UnsupportedOperation {
        /// Adapter name.
        adapter: String,
        /// Operation name.
        operation: String,
    },
    /// Effect inputs, resource, or classification are malformed.
    #[error("effect is invalid for its adapter: {0}")]
    InvalidEffect(String),
    /// A path or network destination is outside configured authority.
    #[error("adapter containment check failed: {0}")]
    Containment(String),
    /// A declared or intrinsic precondition is false.
    #[error("effect precondition failed: {0}")]
    Precondition(String),
    /// State changed after preview or staging.
    #[error("state changed after preview: {0}")]
    Toctou(String),
    /// Adapter-local allowlist or safety policy denied work.
    #[error("adapter policy denied execution: {0}")]
    Policy(String),
    /// Secret reference is unknown or not permitted.
    #[error("secret reference `{provider}:{key}` is unavailable")]
    SecretUnavailable {
        /// Resolver provider name.
        provider: String,
        /// Opaque, non-secret lookup key.
        key: String,
    },
    /// Operation exceeded its deadline.
    #[error("adapter operation timed out")]
    Timeout,
    /// Input, response, file, or process output exceeded an explicit bound.
    #[error("adapter data exceeded the configured {kind} limit of {limit} bytes")]
    SizeLimit {
        /// Bounded data class.
        kind: &'static str,
        /// Configured byte limit.
        limit: usize,
    },
    /// Workspace-relative filesystem operation failed.
    #[error("filesystem adapter could not {operation} `{path}`")]
    Filesystem {
        /// Safe operation description.
        operation: &'static str,
        /// Workspace-relative or internal staging path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// HTTP construction or request failed; the underlying URL is not rendered normally.
    #[error("HTTP adapter request failed")]
    Network(#[source] reqwest::Error),
    /// HTTP destination name resolution failed; the queried hostname is not rendered normally.
    #[error("HTTP destination resolution failed")]
    Resolution(#[source] std::io::Error),
    /// URL or HTTP method parsing failed.
    #[error("HTTP effect contains an invalid {0}")]
    HttpSyntax(&'static str),
    /// Process creation or waiting failed; output is not included.
    #[error("process adapter execution failed")]
    Process(#[source] std::io::Error),
    /// Adapter staging data is malformed or belongs to different effect content.
    #[error("staging evidence is invalid: {0}")]
    InvalidStage(String),
    /// Adapter-generated data could not be serialized.
    #[error("adapter data serialization failed")]
    Serialization(#[source] serde_json::Error),
    /// Canonical effect digest could not be computed.
    #[error("adapter could not digest effect content")]
    Canonical(#[source] veyra_protocol::CanonicalError),
}

impl AdapterError {
    /// Stable machine-readable error code suitable for redacted audit events.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AdapterDisabled(_) => "adapter_disabled",
            Self::DuplicateAdapter(_) => "duplicate_adapter",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::InvalidEffect(_) => "invalid_effect",
            Self::Containment(_) => "containment_failed",
            Self::Precondition(_) => "precondition_failed",
            Self::Toctou(_) => "state_changed",
            Self::Policy(_) => "adapter_policy_denied",
            Self::SecretUnavailable { .. } => "secret_unavailable",
            Self::Timeout => "timeout",
            Self::SizeLimit { .. } => "size_limit",
            Self::Filesystem { .. } => "filesystem_error",
            Self::Network(_) => "network_error",
            Self::Resolution(_) => "dns_error",
            Self::HttpSyntax(_) => "http_syntax",
            Self::Process(_) => "process_error",
            Self::InvalidStage(_) => "invalid_stage",
            Self::Serialization(_) => "serialization_error",
            Self::Canonical(_) => "canonicalization_error",
        }
    }
}
