//! Durable local-instance construction and authentication material.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;
use veyra_core::{FixturePlanner, Kernel, KernelConfig};
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
}

impl RuntimeConfig {
    /// Development-friendly configuration rooted in explicit paths.
    pub fn new(data_directory: PathBuf, workspace_root: PathBuf) -> Self {
        Self {
            data_directory,
            workspace_root,
            workspace_name: "default".into(),
            maximum_file_bytes: 8 * 1024 * 1024,
            maximum_diff_bytes: 256 * 1024,
        }
    }

    /// Path containing the bearer token read by local clients.
    pub fn token_path(&self) -> PathBuf {
        self.data_directory.join("api-token")
    }
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
    fs::create_dir_all(&config.workspace_root).map_err(|source| ServerConfigError::Io {
        operation: "create workspace directory",
        path: config.workspace_root.clone(),
        source,
    })?;
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
        maximum_response_bytes: 2 * 1024 * 1024,
        maximum_timeout_ms: 30_000,
    })?))?;
    adapters.register(Arc::new(ProcessAdapter::new(ProcessAdapterConfig {
        enabled: false,
        rules: vec![],
        maximum_output_bytes: 1024 * 1024,
        maximum_timeout_ms: 30_000,
        allow_shell_executables: false,
    })?))?;
    Ok(Kernel::new(
        journal,
        PolicyEngine::new(PolicyConfig::default()),
        adapters,
        Arc::new(FixturePlanner),
        Arc::new(DenySecretResolver),
        KernelConfig::default(),
    ))
}

fn validate_config(config: &RuntimeConfig) -> Result<(), ServerConfigError> {
    if config.workspace_name.trim().is_empty()
        || config.maximum_file_bytes == 0
        || config.maximum_diff_bytes == 0
        || config.data_directory == config.workspace_root
    {
        return Err(ServerConfigError::Invalid(
            "workspace name and limits must be non-empty, and data must be outside the workspace"
                .into(),
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
    match OpenOptions::new().write(true).create_new(true).open(path) {
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
}
