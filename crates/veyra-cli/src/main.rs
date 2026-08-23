//! Inspectable command-line client for the authenticated local Veyra API.

use std::{io::Read as _, path::PathBuf, sync::Arc, time::Duration};

use clap::{Args, Parser, Subcommand};
use futures_util::StreamExt;
use reqwest::{StatusCode, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tempfile::TempDir;
use thiserror::Error;
use tokio::net::TcpListener;
use veyra_protocol::{
    ApprovalRequestId, AuditVerification, Capability, IntentId, PlanId, Principal, PrincipalId,
    TransactionId,
};
use veyra_server::{
    ApiState, DemoSeed, DemoSeedRequest, GrantApprovalRequest, IssueCapabilityRequest,
    RuntimeConfig, ServerConfigError, TransactionBundle, prepare_instance, serve,
};

const DEFAULT_API_URL: &str = "http://127.0.0.1:7843/v1/";
const MAXIMUM_INPUT_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_TOKEN_FILE_BYTES: usize = 4096;
const MAXIMUM_API_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "veyra", version, about = "Reversible execution for AI agents")]
struct Cli {
    /// Local versioned API root.
    #[arg(long, global = true, env = "VEYRA_API_URL", default_value = DEFAULT_API_URL)]
    api_url: Url,
    /// File containing the local API bearer token.
    #[arg(
        long,
        global = true,
        env = "VEYRA_TOKEN_FILE",
        default_value = ".veyra-data/api-token"
    )]
    token_file: PathBuf,
    /// Emit compact machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize durable local state and a confined workspace.
    Init(InitArguments),
    /// Register an immutable principal from JSON.
    Principal {
        #[command(subcommand)]
        command: PrincipalCommand,
    },
    /// Submit or inspect intents.
    Intent {
        #[command(subcommand)]
        command: IntentCommand,
    },
    /// Inspect a validated plan.
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },
    /// Preview, execute, inspect, or recover a transaction.
    Tx {
        #[command(subcommand)]
        command: TransactionCommand,
    },
    /// Grant an exact content-addressed approval.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Issue a scoped capability from JSON.
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    /// Verify or export the append-only audit journal.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Run a complete no-key create/approve/execute/verify/rollback flow.
    Demo(DemoArguments),
}

#[derive(Debug, Args)]
struct InitArguments {
    /// Durable database and local-key directory.
    #[arg(long, default_value = ".veyra-data")]
    data_directory: PathBuf,
    /// Capability-confined workspace root.
    #[arg(long, default_value = "workspace")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct DemoArguments {
    /// Persist demo state beneath this directory instead of using a temporary directory.
    #[arg(long)]
    directory: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum PrincipalCommand {
    /// Register a human, agent, or service principal.
    Register { file: PathBuf },
}

#[derive(Debug, Subcommand)]
enum IntentCommand {
    /// Submit an intent JSON file to the configured planner.
    Submit { file: PathBuf },
    /// Show one persisted intent.
    Show { id: IntentId },
}

#[derive(Debug, Subcommand)]
enum PlanCommand {
    /// Show one proposed or preflighted plan.
    Show { id: PlanId },
}

#[derive(Debug, Subcommand)]
enum TransactionCommand {
    /// List latest transaction snapshots.
    List {
        /// Maximum snapshots returned in this page (1..=500).
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Opaque cursor returned by a previous page.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Run adapter preflight and policy without executing side effects.
    Preview { id: TransactionId },
    /// Execute and verify an approved transaction.
    Run { id: TransactionId },
    /// Inspect the full causal transaction bundle.
    Inspect { id: TransactionId },
    /// Roll back or compensate supported effects.
    Rollback { id: TransactionId },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// Grant an approval request as a registered human.
    Grant {
        request_id: String,
        #[arg(long)]
        approver: PrincipalId,
    },
}

#[derive(Debug, Subcommand)]
enum CapabilityCommand {
    /// Issue a capability JSON file as a registered human.
    Issue {
        file: PathBuf,
        #[arg(long)]
        issuer: PrincipalId,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify every sequence, previous link, and event hash.
    Verify,
    /// Export a redacted human-readable timeline.
    Export {
        #[arg(long)]
        transaction: Option<TransactionId>,
        /// Maximum events returned in this page (1..=5000).
        #[arg(long, default_value_t = 1_000)]
        limit: usize,
        /// Opaque cursor returned by a previous page.
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let as_json = cli.json;
    match run(cli).await {
        Ok(value) => print_value(&value, as_json),
        Err(error) => {
            eprintln!("veyra: {error}");
            std::process::exit(error.exit_code());
        }
    }
}

async fn run(cli: Cli) -> Result<Value, CliError> {
    match cli.command {
        Command::Init(arguments) => initialize(arguments),
        Command::Demo(arguments) => run_demo(arguments).await,
        command => {
            let client = ApiClient::from_filesystem(cli.api_url, &cli.token_file)?;
            run_remote(&client, command).await
        }
    }
}

fn initialize(arguments: InitArguments) -> Result<Value, CliError> {
    let config = RuntimeConfig::new(arguments.data_directory, arguments.workspace);
    let instance = prepare_instance(&config)?;
    Ok(json!({
        "initialized": true,
        "data_directory": config.data_directory,
        "workspace_root": config.workspace_root,
        "workspace_name": config.workspace_name,
        "token_file": instance.token_path,
        "next": "start veyra-server with matching --data-directory and --workspace paths"
    }))
}

async fn run_remote(client: &ApiClient, command: Command) -> Result<Value, CliError> {
    match command {
        Command::Principal {
            command: PrincipalCommand::Register { file },
        } => {
            let principal: Principal = read_json(&file)?;
            client.post("principals", &principal).await
        }
        Command::Intent {
            command: IntentCommand::Submit { file },
        } => client.post("intents", &read_json::<Value>(&file)?).await,
        Command::Intent {
            command: IntentCommand::Show { id },
        } => client.get(&format!("intents/{id}")).await,
        Command::Plan {
            command: PlanCommand::Show { id },
        } => client.get(&format!("plans/{id}")).await,
        Command::Tx { command } => run_transaction_command(client, command).await,
        Command::Approval {
            command:
                ApprovalCommand::Grant {
                    request_id,
                    approver,
                },
        } => {
            let request_id: ApprovalRequestId = request_id
                .parse()
                .map_err(|_| CliError::Input("invalid approval request ID".into()))?;
            client
                .post(
                    &format!("approvals/{request_id}/grant"),
                    &GrantApprovalRequest {
                        approver_id: approver,
                    },
                )
                .await
        }
        Command::Capability {
            command: CapabilityCommand::Issue { file, issuer },
        } => {
            let capability: Capability = read_json(&file)?;
            client
                .post(
                    "capabilities",
                    &IssueCapabilityRequest {
                        issuer_id: issuer,
                        capability,
                    },
                )
                .await
        }
        Command::Audit { command } => run_audit_command(client, command).await,
        Command::Init(_) | Command::Demo(_) => Err(CliError::Invariant(
            "local command reached the remote dispatcher".into(),
        )),
    }
}

async fn run_transaction_command(
    client: &ApiClient,
    command: TransactionCommand,
) -> Result<Value, CliError> {
    match command {
        TransactionCommand::List { limit, cursor } => {
            client
                .get(&page_path("transactions/page", limit, cursor.as_deref())?)
                .await
        }
        TransactionCommand::Preview { id } => {
            client
                .post_empty(&format!("transactions/{id}/preview"))
                .await
        }
        TransactionCommand::Run { id } => {
            client.post_empty(&format!("transactions/{id}/run")).await
        }
        TransactionCommand::Inspect { id } => {
            client.get(&format!("transactions/{id}/bundle")).await
        }
        TransactionCommand::Rollback { id } => {
            client
                .post_empty(&format!("transactions/{id}/rollback"))
                .await
        }
    }
}

async fn run_audit_command(client: &ApiClient, command: AuditCommand) -> Result<Value, CliError> {
    match command {
        AuditCommand::Verify => client.get("audit/verify").await,
        AuditCommand::Export {
            transaction,
            limit,
            cursor,
        } => {
            if !(1..=5_000).contains(&limit) {
                return Err(CliError::Input(
                    "audit export limit must be within 1..=5000".into(),
                ));
            }
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("limit", &limit.to_string());
            if let Some(cursor) = cursor {
                validate_page_cursor(&cursor)?;
                serializer.append_pair("cursor", &cursor);
            }
            if let Some(transaction) = transaction {
                serializer.append_pair("transaction_id", &transaction.to_string());
            }
            client
                .get(&format!("audit/export?{}", serializer.finish()))
                .await
        }
    }
}

fn page_path(path: &str, limit: usize, cursor: Option<&str>) -> Result<String, CliError> {
    if !(1..=500).contains(&limit) {
        return Err(CliError::Input(
            "transaction page limit must be within 1..=500".into(),
        ));
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        validate_page_cursor(cursor)?;
        serializer.append_pair("cursor", cursor);
    }
    Ok(format!("{path}?{}", serializer.finish()))
}

fn validate_page_cursor(cursor: &str) -> Result<(), CliError> {
    if cursor.is_empty() || cursor.len() > 4_096 || cursor.chars().any(char::is_control) {
        return Err(CliError::Input("page cursor is malformed".into()));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct DemoSummary {
    transaction_id: TransactionId,
    preview_state: String,
    approval_request_id: ApprovalRequestId,
    committed: bool,
    receipt_count: usize,
    verification_count: usize,
    rollback_state: String,
    audit_valid: bool,
    audit_events_checked: u64,
    workspace_file_removed: bool,
}

async fn run_demo(arguments: DemoArguments) -> Result<Value, CliError> {
    let temporary = if arguments.directory.is_none() {
        Some(TempDir::new().map_err(CliError::Io)?)
    } else {
        None
    };
    let root = arguments.directory.unwrap_or_else(|| {
        temporary
            .as_ref()
            .expect("temporary root exists")
            .path()
            .to_owned()
    });
    let config = RuntimeConfig::new(root.join("data"), root.join("workspace"));
    let instance = prepare_instance(&config)?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(CliError::Io)?;
    let address = listener.local_addr().map_err(CliError::Io)?;
    let state = ApiState::new(
        instance.kernel,
        Arc::clone(&instance.token),
        config.workspace_name,
    );
    let server = tokio::spawn(serve(listener, state));
    let client = ApiClient::new(
        Url::parse(&format!("http://{address}/v1/")).map_err(CliError::Url)?,
        instance.token.to_string(),
    )?;
    let result = exercise_demo(&client, &config.workspace_root).await;
    server.abort();
    result
}

async fn exercise_demo(
    client: &ApiClient,
    workspace_root: &std::path::Path,
) -> Result<Value, CliError> {
    let seed: DemoSeed = client
        .post_typed("demo/seed", &DemoSeedRequest::default())
        .await?;
    let transaction_id = seed.submission.transaction.id;
    let preview: Value = client
        .post_typed(&format!("transactions/{transaction_id}/preview"), &())
        .await?;
    let approval_id: ApprovalRequestId = preview
        .pointer("/approval_requests/0/id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Invariant("demo preview did not request approval".into()))?
        .parse()
        .map_err(|_| CliError::Invariant("demo approval ID was malformed".into()))?;
    client
        .post_typed::<_, Value>(
            &format!("approvals/{approval_id}/grant"),
            &GrantApprovalRequest {
                approver_id: seed.human.id,
            },
        )
        .await?;
    let run: Value = client
        .post_typed(&format!("transactions/{transaction_id}/run"), &())
        .await?;
    let bundle: TransactionBundle = client
        .get_typed(&format!("transactions/{transaction_id}/bundle"))
        .await?;
    let rollback: Value = client
        .post_typed(&format!("transactions/{transaction_id}/rollback"), &())
        .await?;
    let audit: AuditVerification = client.get_typed("audit/verify").await?;
    let path = effect_path(&bundle)?;
    serde_json::to_value(DemoSummary {
        transaction_id,
        preview_state: value_string(&preview, "/transaction/state")?,
        approval_request_id: approval_id,
        committed: run
            .get("committed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        receipt_count: bundle.receipts.len(),
        verification_count: bundle.verifications.len(),
        rollback_state: value_string(&rollback, "/transaction/state")?,
        audit_valid: audit.valid,
        audit_events_checked: audit.events_checked,
        workspace_file_removed: !workspace_root.join(path).exists(),
    })
    .map_err(CliError::Json)
}

fn effect_path(bundle: &TransactionBundle) -> Result<&str, CliError> {
    let effect = bundle
        .plan
        .steps
        .first()
        .and_then(|step| step.effects.first())
        .ok_or_else(|| CliError::Invariant("demo plan contained no effect".into()))?;
    match &effect.resource {
        veyra_protocol::ResourceScope::Filesystem { path, .. } => Ok(path),
        _ => Err(CliError::Invariant(
            "demo plan did not contain a filesystem resource".into(),
        )),
    }
}

fn value_string(value: &Value, pointer: &str) -> Result<String, CliError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| CliError::Invariant(format!("API response omitted `{pointer}`")))
}

fn read_json<T: DeserializeOwned>(path: &std::path::Path) -> Result<T, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::Io)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAXIMUM_INPUT_FILE_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(CliError::Io)?;
    if bytes.len() > MAXIMUM_INPUT_FILE_BYTES {
        return Err(CliError::Input(format!(
            "input file exceeds the {MAXIMUM_INPUT_FILE_BYTES}-byte limit"
        )));
    }
    serde_json::from_slice(&bytes).map_err(CliError::Json)
}

fn print_value(value: &Value, compact: bool) {
    let rendered = if compact {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    };
    match rendered {
        Ok(rendered) => println!("{rendered}"),
        Err(error) => {
            eprintln!("veyra: could not render output: {error}");
            std::process::exit(70);
        }
    }
}

#[derive(Clone)]
struct ApiClient {
    client: reqwest::Client,
    root: Url,
    token: Arc<str>,
}

impl ApiClient {
    fn new(mut root: Url, token: String) -> Result<Self, CliError> {
        let loopback = match root.host() {
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        if root.scheme() != "http"
            || !loopback
            || !root.username().is_empty()
            || root.password().is_some()
            || root.query().is_some()
            || root.fragment().is_some()
        {
            return Err(CliError::Input(
                "API URL must use HTTP on an explicit loopback host without credentials, query, or fragment"
                    .into(),
            ));
        }
        if !root.path().ends_with('/') {
            let normalized = format!("{}/", root.path());
            root.set_path(&normalized);
        }
        if token.len() < 64
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(CliError::Input("API token is malformed".into()));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_mins(1))
            .build()
            .map_err(CliError::Http)?;
        Ok(Self {
            client,
            root,
            token: Arc::from(token),
        })
    }

    fn from_filesystem(root: Url, token_file: &std::path::Path) -> Result<Self, CliError> {
        let file = std::fs::File::open(token_file).map_err(CliError::Io)?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAXIMUM_TOKEN_FILE_BYTES).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)
            .map_err(CliError::Io)?;
        if bytes.len() > MAXIMUM_TOKEN_FILE_BYTES {
            return Err(CliError::Input("API token file is too large".into()));
        }
        let token = String::from_utf8(bytes)
            .map_err(|_| CliError::Input("API token is not UTF-8".into()))?
            .trim()
            .to_owned();
        Self::new(root, token)
    }

    async fn get(&self, path: &str) -> Result<Value, CliError> {
        self.get_typed(path).await
    }

    async fn get_typed<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let response = self
            .client
            .get(self.url(path)?)
            .bearer_auth(&*self.token)
            .send()
            .await
            .map_err(CliError::Http)?;
        decode_response(response, &self.token).await
    }

    async fn post<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<Value, CliError> {
        self.post_typed(path, body).await
    }

    async fn post_empty(&self, path: &str) -> Result<Value, CliError> {
        let response = self
            .client
            .post(self.url(path)?)
            .bearer_auth(&*self.token)
            .send()
            .await
            .map_err(CliError::Http)?;
        decode_response(response, &self.token).await
    }

    async fn post_typed<B, T>(&self, path: &str, body: &B) -> Result<T, CliError>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let response = self
            .client
            .post(self.url(path)?)
            .bearer_auth(&*self.token)
            .json(body)
            .send()
            .await
            .map_err(CliError::Http)?;
        decode_response(response, &self.token).await
    }

    fn url(&self, path: &str) -> Result<Url, CliError> {
        let url = self.root.join(path).map_err(CliError::Url)?;
        if url.origin() != self.root.origin() || !url.path().starts_with(self.root.path()) {
            return Err(CliError::Input(
                "API request path escapes the configured versioned root".into(),
            ));
        }
        Ok(url)
    }
}

async fn decode_response<T: DeserializeOwned>(
    response: reqwest::Response,
    token: &str,
) -> Result<T, CliError> {
    let status = response.status();
    if response.content_length().is_some_and(|length| {
        length > u64::try_from(MAXIMUM_API_RESPONSE_BYTES).unwrap_or(u64::MAX)
    }) {
        return Err(CliError::Input(format!(
            "local API response exceeds the {MAXIMUM_API_RESPONSE_BYTES}-byte limit"
        )));
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAXIMUM_API_RESPONSE_BYTES),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(CliError::Http)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAXIMUM_API_RESPONSE_BYTES)
        {
            return Err(CliError::Input(format!(
                "local API response exceeds the {MAXIMUM_API_RESPONSE_BYTES}-byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| value.pointer("/error/message")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| "local API request failed".into());
        return Err(CliError::Api {
            status,
            message: safe_error_message(&message, token),
        });
    }
    serde_json::from_slice(&bytes).map_err(CliError::Json)
}

fn safe_error_message(message: &str, token: &str) -> String {
    message
        .replace(token, "[REDACTED]")
        .chars()
        .take(1_024)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> String {
        format!("vyr_{}{}", PrincipalId::new(), PrincipalId::new()).replace('-', "")
    }

    #[test]
    fn api_client_refuses_to_send_local_authority_to_remote_or_credential_urls() {
        assert!(ApiClient::new(Url::parse("http://127.0.0.1:7843/v1").unwrap(), token()).is_ok());
        assert!(ApiClient::new(Url::parse("http://[::1]:7843/v1").unwrap(), token()).is_ok());
        assert!(ApiClient::new(Url::parse("https://example.com/v1/").unwrap(), token()).is_err());
        assert!(
            ApiClient::new(
                Url::parse("http://operator:secret@127.0.0.1:7843/v1/").unwrap(),
                token(),
            )
            .is_err()
        );

        let client =
            ApiClient::new(Url::parse("http://127.0.0.1:7843/v1/").unwrap(), token()).unwrap();
        assert!(client.url("transactions").is_ok());
        assert!(client.url("../health").is_err());
    }

    #[test]
    fn typed_ids_and_error_rendering_reject_terminal_or_url_injection() {
        assert!(Cli::try_parse_from(["veyra", "tx", "run", "../demo/seed?x="]).is_err());
        let token = token();
        let rendered = safe_error_message(
            &format!("reflected {token}\n\u{1b}[31m{}", "x".repeat(2_000)),
            &token,
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&token));
        assert!(!rendered.chars().any(char::is_control));
        assert_eq!(rendered.chars().count(), 1_024);
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("invalid input: {0}")]
    Input(String),
    #[error("local API returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("local API transport failed: {0}")]
    Http(#[source] reqwest::Error),
    #[error("invalid API URL: {0}")]
    Url(#[source] url::ParseError),
    #[error("local file operation failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("JSON input or response was invalid: {0}")]
    Json(#[source] serde_json::Error),
    #[error(transparent)]
    Configuration(#[from] ServerConfigError),
    #[error("internal CLI invariant failed: {0}")]
    Invariant(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Input(_) | Self::Json(_) | Self::Url(_) => 64,
            Self::Http(error) if error.is_connect() => 69,
            Self::Api { status, .. } if *status == StatusCode::UNAUTHORIZED => 77,
            Self::Api { status, .. } if *status == StatusCode::CONFLICT => 75,
            Self::Io(_) | Self::Configuration(_) => 78,
            Self::Api { .. } | Self::Http(_) | Self::Invariant(_) => 70,
        }
    }
}
