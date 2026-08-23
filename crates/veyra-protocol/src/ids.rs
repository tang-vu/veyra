//! Strongly typed identifiers prevent accidental cross-domain ID use.

use std::{fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident) => {
        #[doc = concat!("Stable identifier for a `", stringify!($name), "` domain object.")]
        #[derive(
            Clone,
            Copy,
            Debug,
            Deserialize,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generate a random, stable identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(PrincipalId);
define_id!(IntentId);
define_id!(PlanId);
define_id!(StepId);
define_id!(EffectId);
define_id!(CapabilityId);
define_id!(PolicyDecisionId);
define_id!(ApprovalRequestId);
define_id!(ApprovalGrantId);
define_id!(ExecutionId);
define_id!(ReceiptId);
define_id!(VerificationId);
define_id!(CompensationId);
define_id!(TransactionId);
define_id!(AuditEventId);
