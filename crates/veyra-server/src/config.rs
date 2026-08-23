//! Durable local-instance construction and authentication material.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use thiserror::Error;
use url::Url;
use veyra_core::{
    FixturePlanner, Kernel, KernelConfig, KernelError, OpenAiCompatiblePlanner,
    OpenAiPlannerConfig, Planner, PlannerError,
};
use veyra_executor::{
    AdapterError, AdapterRegistry, DenySecretResolver, FilesystemAdapter, FilesystemConfig,
    HttpAdapter, HttpAdapterConfig, ProcessAdapter, ProcessAdapterConfig,
};
use veyra_journal::{Journal, JournalError};
use veyra_policy::{PolicyConfig, PolicyEngine};
use veyra_protocol::PrincipalId;

/// Paths and bounded adapter settings for one local Veyra instance.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Directory containing the database and local authentication material.
    pub data_directory: PathBuf,
    /// Filesystem capability root exposed under `workspace_name`.
    pub workspace_root: PathBuf,
    /// Stable protocol name for the workspace capability.
    pub workspace_name: String,
    /// Maximum size of an individual workspace file.
    pub maximum_file_bytes: usize,
    /// Maximum structured diff bytes stored in an approval preview.
    pub maximum_diff_bytes: usize,
    /// Model-independent planner implementation. Fixture mode is the safe offline default.
    pub planner: PlannerRuntimeConfig,
}

impl RuntimeConfig {
    /// Development-friendly configuration rooted in explicit paths.
    pub fn new(data_directory: PathBuf, workspace_root: PathBuf) -> Self {
        Self {
            data_directory,
            workspace_root,
            workspace_name: "default".into(),
            maximum_file_bytes: 256 * 1024,
            maximum_diff_bytes: 256 * 1024,
            planner: PlannerRuntimeConfig::Fixture,
        }
    }

    /// Path containing the bearer token read by local clients.
    pub fn token_path(&self) -> PathBuf {
        self.data_directory.join("api-token")
    }
}

/// Planner selection for a local server instance.
#[derive(Clone, Debug)]
pub enum PlannerRuntimeConfig {
    /// Deterministic no-key planner used by tests and demos.
    Fixture,
    /// `OpenAI` Responses-compatible endpoint with strict schema output.
    OpenAiCompatible {
        /// Full HTTPS Responses endpoint.
        endpoint: Url,
        /// Provider model identifier.
        model: String,
        /// Environment variable resolved only when a request is made.
        api_key_environment: String,
        /// Provider deadline.
        timeout: Duration,
    },
}

/// Ready-to-serve trusted kernel and secret local API token.
#[derive(Clone)]
pub struct PreparedInstance {
    /// Trusted execution kernel.
    pub kernel: Kernel,
    /// Random local bearer token. Never log or serialize this value.
    pub token: Arc<str>,
    /// File from which local clients can read the bearer token.
    pub token_path: PathBuf,
}

/// Initialize durable state, constrained adapters, and local API authentication.
///
/// # Errors
///
/// Returns [`ServerConfigError`] when paths, authentication material, the journal, or an adapter
/// cannot be initialized safely.
pub fn prepare_instance(config: &RuntimeConfig) -> Result<PreparedInstance, ServerConfigError> {
    validate_config(config)?;
    fs::create_dir_all(&config.data_directory).map_err(|source| ServerConfigError::Io {
        operation: "create data directory",
        path: config.data_directory.clone(),
        source,
    })?;
    secure_data_directory(&config.data_directory)?;
    fs::create_dir_all(&config.workspace_root).map_err(|source| ServerConfigError::Io {
        operation: "create workspace directory",
        path: config.workspace_root.clone(),
        source,
    })?;
    validate_disjoint_roots(&config.data_directory, &config.workspace_root)?;
    let demo_directory = config.workspace_root.join("demo");
    fs::create_dir_all(&demo_directory).map_err(|source| ServerConfigError::Io {
        operation: "create demo workspace directory",
        path: demo_directory,
        source,
    })?;
    let journal = Journal::open(
        config.data_directory.join("veyra.sqlite3"),
        config.data_directory.join("receipt.key"),
    )?;
    let kernel = build_kernel(config, journal)?;
    kernel.recover_after_restart()?;
    let token_path = config.token_path();
    let token = Arc::<str>::from(load_or_create_token(&token_path)?);
    Ok(PreparedInstance {
        kernel,
        token,
        token_path,
    })
}

fn build_kernel(config: &RuntimeConfig, journal: Journal) -> Result<Kernel, ServerConfigError> {
    let mut adapters = AdapterRegistry::new();
    adapters.register(Arc::new(FilesystemAdapter::new(FilesystemConfig {
        workspace_name: config.workspace_name.clone(),
        root: config.workspace_root.clone(),
        maximum_file_bytes: config.maximum_file_bytes,
        maximum_diff_bytes: config.maximum_diff_bytes,
    })?))?;
    adapters.register(Arc::new(HttpAdapter::new(HttpAdapterConfig {
        rules: vec![],
        maximum_request_bytes: 1024 * 1024,
        maximum_request_header_bytes: 64 * 1024,
        maximum_response_bytes: 256 * 1024,
        maximum_response_header_bytes: 64 * 1024,
        maximum_timeout_ms: 30_000,
    })?))?;
    adapters.register(Arc::new(ProcessAdapter::new(ProcessAdapterConfig {
        enabled: false,
        rules: vec![],
        maximum_output_bytes: 256 * 1024,
        maximum_timeout_ms: 30_000,
        allow_shell_executables: false,
    })?))?;
    let planner: Arc<dyn Planner> = match &config.planner {
        PlannerRuntimeConfig::Fixture => Arc::new(FixturePlanner),
        PlannerRuntimeConfig::OpenAiCompatible {
            endpoint,
            model,
            api_key_environment,
            timeout,
        } => Arc::new(OpenAiCompatiblePlanner::new(OpenAiPlannerConfig {
            endpoint: endpoint.clone(),
            model: model.clone(),
            api_key_environment: api_key_environment.clone(),
            timeout: *timeout,
            maximum_response_bytes: 2 * 1024 * 1024,
        })?),
    };
    Ok(Kernel::new(
        journal,
        PolicyEngine::new(PolicyConfig::default()),
        adapters,
        planner,
        Arc::new(DenySecretResolver),
        KernelConfig::default(),
    ))
}

fn validate_config(config: &RuntimeConfig) -> Result<(), ServerConfigError> {
    if config.workspace_name.trim().is_empty()
        || config.maximum_file_bytes == 0
        || config.maximum_diff_bytes == 0
        || config.data_directory == config.workspace_root
        || matches!(
            &config.planner,
            PlannerRuntimeConfig::OpenAiCompatible {
                model,
                api_key_environment,
                ..
            } if model.trim().is_empty() || api_key_environment.trim().is_empty()
        )
    {
        return Err(ServerConfigError::Invalid(
            "workspace name and limits must be non-empty, and data/workspace paths must differ"
                .into(),
        ));
    }
    Ok(())
}

fn validate_disjoint_roots(data: &Path, workspace: &Path) -> Result<(), ServerConfigError> {
    let canonical_data = fs::canonicalize(data).map_err(|source| ServerConfigError::Io {
        operation: "canonicalize data directory",
        path: data.to_owned(),
        source,
    })?;
    let canonical_workspace =
        fs::canonicalize(workspace).map_err(|source| ServerConfigError::Io {
            operation: "canonicalize workspace directory",
            path: workspace.to_owned(),
            source,
        })?;
    if canonical_data.starts_with(&canonical_workspace)
        || canonical_workspace.starts_with(&canonical_data)
    {
        return Err(ServerConfigError::Invalid(
            "data and workspace directories must have disjoint canonical roots".into(),
        ));
    }
    Ok(())
}

fn load_or_create_token(path: &Path) -> Result<String, ServerConfigError> {
    match read_token(path) {
        Ok(token) => return Ok(token),
        Err(ServerConfigError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let token = format!("vyr_{}{}", PrincipalId::new(), PrincipalId::new()).replace('-', "");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(token.as_bytes())
                .map_err(|source| ServerConfigError::Io {
                    operation: "write API token",
                    path: path.to_owned(),
                    source,
                })?;
            file.sync_all().map_err(|source| ServerConfigError::Io {
                operation: "sync API token",
                path: path.to_owned(),
                source,
            })?;
            Ok(token)
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => read_token(path),
        Err(source) => Err(ServerConfigError::Io {
            operation: "create API token",
            path: path.to_owned(),
            source,
        }),
    }
}

fn read_token(path: &Path) -> Result<String, ServerConfigError> {
    const MAXIMUM_TOKEN_FILE_BYTES: u64 = 4_096;
    let metadata = fs::symlink_metadata(path).map_err(|source| ServerConfigError::Io {
        operation: "inspect API token",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ServerConfigError::Invalid(
            "API token must be a regular, non-symlink file".into(),
        ));
    }
    if metadata.len() > MAXIMUM_TOKEN_FILE_BYTES {
        return Err(ServerConfigError::Invalid(
            "API token file exceeds 4096 bytes".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ServerConfigError::Invalid(
                "API token permissions must deny group and other access".into(),
            ));
        }
    }
    let mut token = String::new();
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|mut file| file.read_to_string(&mut token))
        .map_err(|source| ServerConfigError::Io {
            operation: "read API token",
            path: path.to_owned(),
            source,
        })?;
    let token = token.trim().to_owned();
    if token.len() < 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ServerConfigError::Invalid(
            "API token file contains malformed authentication material".into(),
        ));
    }
    Ok(token)
}

fn secure_data_directory(path: &Path) -> Result<(), ServerConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ServerConfigError::Io {
        operation: "inspect data directory",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ServerConfigError::Invalid(
            "data directory must be a real directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ServerConfigError::Io {
                operation: "restrict data directory permissions",
                path: path.to_owned(),
                source,
            }
        })?;
    }
    Ok(())
}

/// Local-instance configuration failure with path-aware, credential-safe diagnostics.
#[derive(Debug, Error)]
pub enum ServerConfigError {
    /// Runtime configuration violates a safe local invariant.
    #[error("invalid server configuration: {0}")]
    Invalid(String),
    /// A local file operation failed.
    #[error("could not {operation} at {path}: {source}")]
    Io {
        /// Safe operation name.
        operation: &'static str,
        /// Affected local path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Journal initialization failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Adapter initialization failed.
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    /// Model provider configuration failed.
    #[error(transparent)]
    Planner(#[from] PlannerError),
    /// Persisted transaction recovery failed.
    #[error(transparent)]
    Kernel(#[from] KernelError),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn journal_and_workspace_roots_must_not_overlap() {
        let temporary = TempDir::new().unwrap();
        let workspace = temporary.path().join("workspace");
        let data = workspace.join("private-data");
        let config = RuntimeConfig::new(data, workspace);

        let error = prepare_instance(&config).err().unwrap();
        assert!(error.to_string().contains("disjoint canonical roots"));
    }

    #[test]
    fn configured_planner_refuses_cleartext_endpoints() {
        let temporary = TempDir::new().unwrap();
        let mut config = RuntimeConfig::new(
            temporary.path().join("data"),
            temporary.path().join("workspace"),
        );
        config.planner = PlannerRuntimeConfig::OpenAiCompatible {
            endpoint: Url::parse("http://127.0.0.1/v1/responses").unwrap(),
            model: "fixture-model".into(),
            api_key_environment: "VEYRA_TEST_API_KEY".into(),
            timeout: Duration::from_secs(1),
        };

        let error = prepare_instance(&config).err().unwrap();
        assert!(error.to_string().contains("must be an HTTPS URL"));
    }

    #[test]
    fn reopening_an_instance_persists_manual_recovery_state() {
        let temporary = TempDir::new().unwrap();
        let config = RuntimeConfig::new(
            temporary.path().join("data"),
            temporary.path().join("workspace"),
        );
        let transaction_id = veyra_protocol::TransactionId::new();
        {
            let instance = prepare_instance(&config).unwrap();
            let now = chrono::Utc::now();
            instance
                .kernel
                .journal()
                .create_transaction(&veyra_protocol::Transaction {
                    schema_version: veyra_protocol::PROTOCOL_VERSION.into(),
                    id: transaction_id,
                    intent_id: veyra_protocol::IntentId::new(),
                    plan_id: veyra_protocol::PlanId::new(),
                    state: veyra_protocol::TransactionState::Executing,
                    effect_ids: vec![],
                    receipt_ids: vec![],
                    revision: 0,
                    created_at: now,
                    updated_at: now,
                    manual_recovery_reason: None,
                })
                .unwrap();
        }

        let reopened = prepare_instance(&config).unwrap();
        let recovered = reopened
            .kernel
            .journal()
            .transaction(transaction_id)
            .unwrap();
        assert_eq!(
            recovered.state,
            veyra_protocol::TransactionState::ManualRecovery
        );
        assert!(recovered.manual_recovery_reason.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_api_token_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new().unwrap();
        let config = RuntimeConfig::new(
            temporary.path().join("data"),
            temporary.path().join("workspace"),
        );
        let instance = prepare_instance(&config).unwrap();
        let mode = fs::metadata(instance.token_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let directory_mode = fs::metadata(config.data_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
    }
}
