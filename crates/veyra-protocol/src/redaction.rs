//! Secret-safe effect inputs. Secrets cross the kernel only as opaque references.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// A typed input entry that is safe to serialize into plans and audit records.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputValue {
    /// Non-sensitive data that may appear in previews and audit exports.
    Public {
        /// JSON value known to be non-sensitive.
        value: Value,
    },
    /// An opaque lookup reference. The referenced secret is resolved only at the adapter boundary.
    SecretRef {
        /// Secret-provider name, such as `environment` or an OS keyring adapter.
        provider: String,
        /// Provider-local opaque key. It must not itself contain the secret.
        key: String,
        /// Safe text rendered in previews and audit exports.
        redacted: String,
    },
}

/// Deterministically ordered effect input map.
pub type EffectInputs = BTreeMap<String, InputValue>;

/// Error returned when an adapter requests an input with the wrong public type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InputError {
    /// No input exists under the requested key.
    #[error("missing required input `{0}`")]
    Missing(String),
    /// The input is a secret reference and cannot be read as public data.
    #[error("input `{0}` is a secret reference")]
    Secret(String),
    /// The JSON value does not have the requested type.
    #[error("input `{key}` must be {expected}")]
    WrongType {
        /// Input key.
        key: String,
        /// Human-readable expected type.
        expected: &'static str,
    },
}

/// Read a public string without allowing adapters to accidentally expose secret references.
///
/// # Errors
///
/// Returns [`InputError`] when the key is absent, secret, or not a string.
pub fn public_string<'a>(inputs: &'a EffectInputs, key: &str) -> Result<&'a str, InputError> {
    match inputs.get(key) {
        None => Err(InputError::Missing(key.to_owned())),
        Some(InputValue::SecretRef { .. }) => Err(InputError::Secret(key.to_owned())),
        Some(InputValue::Public { value }) => value.as_str().ok_or_else(|| InputError::WrongType {
            key: key.to_owned(),
            expected: "a string",
        }),
    }
}

/// Build a public input value.
pub fn public(value: impl Into<Value>) -> InputValue {
    InputValue::Public {
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_serialization_contains_only_reference_and_marker() {
        let value = InputValue::SecretRef {
            provider: "environment".into(),
            key: "SERVICE_TOKEN".into(),
            redacted: "[REDACTED]".into(),
        };
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(serialized.contains("SERVICE_TOKEN"));
        assert!(serialized.contains("[REDACTED]"));
        assert!(!serialized.contains("secret-value"));
    }
}
