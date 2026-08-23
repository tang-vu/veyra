//! Generate committed JSON Schemas from authoritative Rust protocol types.

use std::{fs, path::PathBuf};

use schemars::{JsonSchema, schema_for};
use serde::Serialize;
use veyra_protocol::{
    ApprovalGrant, ApprovalRequest, AuditEvent, AuditVerification, Capability, Compensation,
    Effect, Execution, Intent, Plan, PolicyDecision, Principal, Receipt, Step, Transaction,
    Verification,
};

fn write_schema<T: JsonSchema + ?Sized>(
    directory: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = schema_for!(T);
    let serialized = serde_json::to_string_pretty(&SchemaDocument {
        protocol: veyra_protocol::PROTOCOL_VERSION,
        schema,
    })?;
    fs::write(
        directory.join(format!("{name}.schema.json")),
        format!("{serialized}\n"),
    )?;
    Ok(())
}

#[derive(Serialize)]
struct SchemaDocument<T> {
    #[serde(rename = "x-veyra-protocol")]
    protocol: &'static str,
    #[serde(flatten)]
    schema: T,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("packages/protocol-schema/schema"));
    fs::create_dir_all(&directory)?;
    write_schema::<Principal>(&directory, "principal")?;
    write_schema::<Intent>(&directory, "intent")?;
    write_schema::<Plan>(&directory, "plan")?;
    write_schema::<Step>(&directory, "step")?;
    write_schema::<Effect>(&directory, "effect")?;
    write_schema::<Capability>(&directory, "capability")?;
    write_schema::<PolicyDecision>(&directory, "policy-decision")?;
    write_schema::<ApprovalRequest>(&directory, "approval-request")?;
    write_schema::<ApprovalGrant>(&directory, "approval-grant")?;
    write_schema::<Execution>(&directory, "execution")?;
    write_schema::<Receipt>(&directory, "receipt")?;
    write_schema::<Verification>(&directory, "verification")?;
    write_schema::<Compensation>(&directory, "compensation")?;
    write_schema::<Transaction>(&directory, "transaction")?;
    write_schema::<AuditEvent>(&directory, "audit-event")?;
    write_schema::<AuditVerification>(&directory, "audit-verification")?;
    println!("generated protocol schemas in {}", directory.display());
    Ok(())
}
