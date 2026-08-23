//! Secret resolution is deliberately isolated at the adapter boundary.

use std::{collections::HashSet, fmt};
use zeroize::Zeroizing;

use crate::AdapterError;

/// Secret bytes that redact debug output and zero their allocation on drop.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wrap newly resolved secret bytes.
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Expose bytes only inside an adapter's final request/process construction boundary.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Resolver available only to registered adapters during final request construction.
pub trait SecretResolver: Send + Sync {
    /// Resolve one opaque reference.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::SecretUnavailable`] for unknown providers or keys.
    fn resolve(&self, provider: &str, key: &str) -> Result<SecretValue, AdapterError>;
}

/// Resolver that denies every lookup. It is the safe default for demos and tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenySecretResolver;

impl SecretResolver for DenySecretResolver {
    fn resolve(&self, provider: &str, key: &str) -> Result<SecretValue, AdapterError> {
        Err(AdapterError::SecretUnavailable {
            provider: provider.to_owned(),
            key: key.to_owned(),
        })
    }
}

/// Environment resolver with an explicit variable-name allowlist.
#[derive(Clone, Debug)]
pub struct EnvironmentSecretResolver {
    allowed_keys: HashSet<String>,
}

impl EnvironmentSecretResolver {
    /// Create a resolver that exposes only the supplied environment variable names.
    pub fn new(allowed_keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_keys: allowed_keys.into_iter().collect(),
        }
    }
}

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, provider: &str, key: &str) -> Result<SecretValue, AdapterError> {
        if provider != "environment" || !self.allowed_keys.contains(key) {
            return Err(AdapterError::SecretUnavailable {
                provider: provider.to_owned(),
                key: key.to_owned(),
            });
        }
        let value = std::env::var_os(key).ok_or_else(|| AdapterError::SecretUnavailable {
            provider: provider.to_owned(),
            key: key.to_owned(),
        })?;
        Ok(SecretValue::new(
            value.to_string_lossy().into_owned().into_bytes(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_secret() {
        let secret = SecretValue::new(b"highly-sensitive".to_vec());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("highly-sensitive"));
        assert!(debug.contains("REDACTED"));
    }
}
