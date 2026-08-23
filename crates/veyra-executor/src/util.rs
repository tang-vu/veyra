//! Shared adapter parsing, hashing, and bounded-data helpers.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use veyra_protocol::{EffectInputs, InputValue};

use crate::AdapterError;

pub(crate) fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn public_value<'a>(
    inputs: &'a EffectInputs,
    key: &str,
) -> Result<&'a Value, AdapterError> {
    match inputs.get(key) {
        Some(InputValue::Public { value }) => Ok(value),
        Some(InputValue::SecretRef { .. }) => Err(AdapterError::InvalidEffect(format!(
            "`{key}` must be public adapter input"
        ))),
        None => Err(AdapterError::InvalidEffect(format!(
            "missing required input `{key}`"
        ))),
    }
}

pub(crate) fn public_string<'a>(
    inputs: &'a EffectInputs,
    key: &str,
) -> Result<&'a str, AdapterError> {
    public_value(inputs, key)?
        .as_str()
        .ok_or_else(|| AdapterError::InvalidEffect(format!("input `{key}` must be a string")))
}

pub(crate) fn public_string_array(
    inputs: &EffectInputs,
    key: &str,
) -> Result<Vec<String>, AdapterError> {
    public_value(inputs, key)?
        .as_array()
        .ok_or_else(|| AdapterError::InvalidEffect(format!("input `{key}` must be an array")))?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                AdapterError::InvalidEffect(format!(
                    "every value in input `{key}` must be a string"
                ))
            })
        })
        .collect()
}

pub(crate) fn public_string_map(
    inputs: &EffectInputs,
    key: &str,
) -> Result<BTreeMap<String, String>, AdapterError> {
    public_value(inputs, key)?
        .as_object()
        .ok_or_else(|| AdapterError::InvalidEffect(format!("input `{key}` must be an object")))?
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| {
                    AdapterError::InvalidEffect(format!(
                        "every value in input `{key}` must be a string"
                    ))
                })
        })
        .collect()
}

pub(crate) fn no_secret_inputs(inputs: &EffectInputs) -> Result<(), AdapterError> {
    if let Some(key) = inputs
        .iter()
        .find_map(|(key, value)| matches!(value, InputValue::SecretRef { .. }).then_some(key))
    {
        Err(AdapterError::InvalidEffect(format!(
            "adapter operation does not accept secret input `{key}`"
        )))
    } else {
        Ok(())
    }
}
