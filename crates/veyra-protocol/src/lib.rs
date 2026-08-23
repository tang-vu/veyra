//! Authoritative, versioned domain and wire types shared by every Veyra client.

mod canonical;
mod ids;
mod model;
mod redaction;

pub use canonical::{CanonicalError, canonical_digest, canonical_json};
pub use ids::*;
pub use model::*;
pub use redaction::*;

/// Current protocol identifier. Breaking wire changes require a new value.
pub const PROTOCOL_VERSION: &str = "veyra.protocol/v1";
