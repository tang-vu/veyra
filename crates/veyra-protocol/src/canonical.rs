//! RFC 8785 canonical JSON helpers used for approvals and audit evidence.

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical serialization failure.
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// The value could not be represented as canonical JSON.
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Serialize a value using the JSON Canonicalization Scheme.
///
/// # Errors
///
/// Returns [`CanonicalError`] if the value contains data JSON cannot represent.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_jcs::to_vec(value).map_err(CanonicalError::from)
}

/// SHA-256 digest of a value's canonical JSON, encoded as lowercase hex.
///
/// # Errors
///
/// Returns [`CanonicalError`] if the value cannot be canonically serialized.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(canonical_json(value)?);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn object_key_order_does_not_change_digest() {
        let first = json!({"z": 1, "a": {"two": 2, "one": 1}});
        let second: serde_json::Value =
            serde_json::from_str(r#"{"a":{"one":1,"two":2},"z":1}"#).unwrap();
        assert_eq!(
            canonical_digest(&first).unwrap(),
            canonical_digest(&second).unwrap()
        );
    }
}
