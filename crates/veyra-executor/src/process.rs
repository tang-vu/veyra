//! Disabled-by-default, argv-only process adapter with exact executable policy and bounded output.

use std::{
    collections::BTreeSet,
    io::Read as _,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex, time::timeout};
use veyra_protocol::{
    Condition, Effect, InputValue, Preview, ResourceScope, Reversibility, VerificationCheck,
};

use crate::{
    AdapterContext, AdapterError, AdapterPreflight, AdapterRecovery, AdapterResult, EffectAdapter,
    SecretValue, StagedEffect,
    util::{public_string_array, sha256},
};

/// One exact executable, argument-vector, working-directory, and environment allowlist.
#[derive(Clone, Debug)]
pub struct ProcessRule {
    /// Trusted executable path. It is canonicalized when the adapter is created.
    pub executable: PathBuf,
    /// Exact argument vectors that may be used.
    pub argument_sets: Vec<Vec<String>>,
    /// Exact working directories that may be used.
    pub workdirs: Vec<PathBuf>,
    /// Environment variable names that may be resolved from secret references.
    pub environment_keys: BTreeSet<String>,
}

/// Process adapter policy and hard limits.
#[derive(Clone, Debug)]
pub struct ProcessAdapterConfig {
    /// Master switch. False is the default expected production posture.
    pub enabled: bool,
    /// Exact allowlist rules.
    pub rules: Vec<ProcessRule>,
    /// Maximum combined captured stdout and stderr bytes.
    pub maximum_output_bytes: usize,
    /// Maximum runtime regardless of effect request.
    pub maximum_timeout_ms: u64,
    /// Permit explicitly allowlisted shell executables. False prevents common shells entirely.
    pub allow_shell_executables: bool,
}

/// Exact-policy process adapter.
#[derive(Clone, Debug)]
pub struct ProcessAdapter {
    config: ProcessAdapterConfig,
    rules: Vec<CanonicalProcessRule>,
}

impl ProcessAdapter {
    /// Validate and canonicalize a process configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] for zero limits, missing executables/workdirs, empty argument
    /// allowlists, or a common shell when shell execution is not explicitly enabled.
    pub fn new(config: ProcessAdapterConfig) -> Result<Self, AdapterError> {
        if config.maximum_output_bytes == 0 || config.maximum_timeout_ms == 0 {
            return Err(AdapterError::Policy(
                "process output and timeout limits must be positive".into(),
            ));
        }
        let rules = config
            .rules
            .iter()
            .map(|rule| canonical_rule(rule, config.allow_shell_executables))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { config, rules })
    }

    /// Build the safe demo policy for one exact executable, argument vector, and working directory.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if either path cannot be canonicalized.
    pub fn safe_demo(
        executable: impl AsRef<Path>,
        arguments: Vec<String>,
        workdir: impl AsRef<Path>,
    ) -> Result<Self, AdapterError> {
        Self::new(ProcessAdapterConfig {
            enabled: true,
            rules: vec![ProcessRule {
                executable: executable.as_ref().to_path_buf(),
                argument_sets: vec![arguments],
                workdirs: vec![workdir.as_ref().to_path_buf()],
                environment_keys: BTreeSet::new(),
            }],
            maximum_output_bytes: 64 * 1024,
            maximum_timeout_ms: 5_000,
            allow_shell_executables: false,
        })
    }

    fn spec(&self, effect: &Effect) -> Result<ProcessSpec, AdapterError> {
        if !self.config.enabled {
            return Err(AdapterError::AdapterDisabled(self.name().into()));
        }
        if effect.adapter != self.name() {
            return Err(AdapterError::InvalidEffect(
                "adapter field is not `process`".into(),
            ));
        }
        if effect.operation != "run" {
            return Err(AdapterError::UnsupportedOperation {
                adapter: self.name().into(),
                operation: effect.operation.clone(),
            });
        }
        if effect.reversibility != Reversibility::Irreversible {
            return Err(AdapterError::InvalidEffect(
                "process execution must declare `irreversible`".into(),
            ));
        }
        if effect.timeout_ms == 0 || effect.timeout_ms > self.config.maximum_timeout_ms {
            return Err(AdapterError::Policy(
                "effect timeout exceeds process adapter limit".into(),
            ));
        }
        if effect.expected_postconditions.is_empty() {
            return Err(AdapterError::InvalidEffect(
                "process effect must declare at least one output or exit-code postcondition".into(),
            ));
        }
        let ResourceScope::Process {
            executable,
            workdir,
        } = &effect.resource
        else {
            return Err(AdapterError::InvalidEffect(
                "process effect has a non-process resource".into(),
            ));
        };
        let executable = std::fs::canonicalize(executable).map_err(AdapterError::Process)?;
        let workdir = std::fs::canonicalize(workdir).map_err(AdapterError::Process)?;
        let arguments = public_string_array(&effect.inputs, "args")?;
        let rule = self
            .rules
            .iter()
            .find(|rule| {
                rule.executable == executable
                    && rule.workdirs.contains(&workdir)
                    && rule.argument_sets.contains(&arguments)
            })
            .ok_or_else(|| {
                AdapterError::Policy(
                    "executable, argv, or working directory is not exactly allowlisted".into(),
                )
            })?;
        let mut environment = Vec::new();
        for (input_key, value) in &effect.inputs {
            if let InputValue::SecretRef { provider, key, .. } = value {
                let name = input_key.strip_prefix("env:").ok_or_else(|| {
                    AdapterError::InvalidEffect(
                        "process secret inputs must use an `env:<name>` key".into(),
                    )
                })?;
                if !valid_environment_name(name) || !rule.environment_keys.contains(name) {
                    return Err(AdapterError::Policy(
                        "environment variable is not explicitly allowlisted".into(),
                    ));
                }
                environment.push(ProcessEnvironment {
                    name: name.to_owned(),
                    provider: provider.clone(),
                    key: key.clone(),
                });
            }
        }
        environment.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(ProcessSpec {
            executable,
            arguments,
            workdir,
            environment,
        })
    }

    fn decode_stage(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
    ) -> Result<ProcessStage, AdapterError> {
        if staged.adapter != self.name() || staged.effect_id != effect.id {
            return Err(AdapterError::InvalidStage(
                "process stage binding mismatch".into(),
            ));
        }
        if staged.effect_digest != effect.content_digest().map_err(AdapterError::Canonical)? {
            return Err(AdapterError::InvalidStage(
                "process effect changed after staging".into(),
            ));
        }
        serde_json::from_value(staged.data.clone()).map_err(AdapterError::Serialization)
    }

    async fn executable_digest(path: PathBuf) -> Result<String, AdapterError> {
        tokio::task::spawn_blocking(move || hash_file(&path, 512 * 1024 * 1024))
            .await
            .map_err(|_| AdapterError::Policy("executable digest task failed".into()))?
    }
}

#[async_trait]
impl EffectAdapter for ProcessAdapter {
    fn name(&self) -> &'static str {
        "process"
    }

    fn validate(&self, effect: &Effect) -> Result<(), AdapterError> {
        let _ = self.spec(effect)?;
        Ok(())
    }

    async fn preflight(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<AdapterPreflight, AdapterError> {
        let spec = self.spec(effect)?;
        let executable_digest = Self::executable_digest(spec.executable.clone()).await?;
        Ok(AdapterPreflight {
            preview: process_preview(&spec),
            observations: json!({
                "executable_sha256": executable_digest,
                "shell_interpolation": false,
                "output_limit_bytes": self.config.maximum_output_bytes,
            }),
        })
    }

    async fn stage(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<StagedEffect, AdapterError> {
        let spec = self.spec(effect)?;
        if effect.preview != process_preview(&spec) {
            return Err(AdapterError::Toctou(
                "process preview changed before staging".into(),
            ));
        }
        let stage = ProcessStage {
            spec_digest: process_spec_digest(&spec)?,
            executable_digest: Self::executable_digest(spec.executable).await?,
        };
        Ok(StagedEffect {
            adapter: self.name().into(),
            effect_id: effect.id,
            effect_digest: effect.content_digest().map_err(AdapterError::Canonical)?,
            data: serde_json::to_value(stage).map_err(AdapterError::Serialization)?,
            staged_at: Utc::now(),
        })
    }

    async fn execute(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        let stage = self.decode_stage(effect, staged)?;
        let spec = self.spec(effect)?;
        if stage.spec_digest != process_spec_digest(&spec)?
            || stage.executable_digest != Self::executable_digest(spec.executable.clone()).await?
        {
            return Err(AdapterError::Toctou(
                "executable or process specification changed after staging".into(),
            ));
        }

        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.arguments)
            .current_dir(&spec.workdir)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut secrets = Vec::<SecretValue>::new();
        for environment in &spec.environment {
            let secret = context
                .secrets
                .resolve(&environment.provider, &environment.key)?;
            let value = std::str::from_utf8(secret.expose()).map_err(|_| {
                AdapterError::Policy("process environment secret must be UTF-8".into())
            })?;
            command.env(&environment.name, value);
            secrets.push(secret);
        }
        let mut child = command.spawn().map_err(AdapterError::Process)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdapterError::Policy("process stdout was not captured".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AdapterError::Policy("process stderr was not captured".into()))?;
        let capture = Arc::new(Mutex::new(OutputCapture::default()));
        let future = async {
            let status_future = child.wait();
            let stdout_future = drain_output(
                stdout,
                capture.clone(),
                OutputStream::Stdout,
                self.config.maximum_output_bytes,
            );
            let stderr_future = drain_output(
                stderr,
                capture.clone(),
                OutputStream::Stderr,
                self.config.maximum_output_bytes,
            );
            let (status, (), ()) = tokio::try_join!(status_future, stdout_future, stderr_future)
                .map_err(AdapterError::Process)?;
            Ok::<_, AdapterError>(status)
        };
        let status = Box::pin(timeout(Duration::from_millis(effect.timeout_ms), future))
            .await
            .map_err(|_| AdapterError::Timeout)??;
        let capture = Arc::try_unwrap(capture)
            .map_err(|_| AdapterError::Policy("process output capture remained shared".into()))?
            .into_inner();
        if capture.exceeded {
            return Err(AdapterError::SizeLimit {
                kind: "process output",
                limit: self.config.maximum_output_bytes,
            });
        }
        let mut stdout = String::from_utf8_lossy(&capture.stdout).into_owned();
        let mut stderr = String::from_utf8_lossy(&capture.stderr).into_owned();
        for secret in &secrets {
            if let Ok(value) = std::str::from_utf8(secret.expose())
                && !value.is_empty()
            {
                stdout = stdout.replace(value, "[REDACTED]");
                stderr = stderr.replace(value, "[REDACTED]");
            }
        }
        drop(secrets);
        let exit_code = status.code();
        let digest =
            sha256(format!("exit={exit_code:?}\nstdout={stdout}\nstderr={stderr}").as_bytes());
        Ok(AdapterResult {
            outcome: exit_code.map_or_else(
                || "terminated_by_signal".into(),
                |code| format!("exit_{code}"),
            ),
            data: json!({
                "exit_code": exit_code,
                "success": status.success(),
                "stdout": stdout,
                "stderr": stderr,
            }),
            post_state_digest: Some(digest),
        })
    }

    async fn verify(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        result: &AdapterResult,
        _context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError> {
        let _ = self.decode_stage(effect, staged)?;
        let exit_code = result
            .data
            .get("exit_code")
            .and_then(serde_json::Value::as_i64);
        let mut checks = vec![VerificationCheck {
            condition: Condition::Custom {
                name: "veyra.process.completed/v1".into(),
                parameters: json!({}),
            },
            passed: result
                .data
                .get("success")
                .and_then(serde_json::Value::as_bool)
                .is_some(),
            message: "process completion metadata parsed".into(),
        }];
        for condition in &effect.expected_postconditions {
            let (passed, message) = match condition {
                Condition::OutputSha256 { digest } => (
                    result.post_state_digest.as_deref() == Some(digest),
                    "combined output digest checked".into(),
                ),
                Condition::Custom { name, parameters } if name == "veyra.process.exit_code/v1" => {
                    let expected = parameters
                        .get("expected")
                        .and_then(serde_json::Value::as_i64);
                    (
                        exit_code == expected,
                        format!("observed exit code {exit_code:?}"),
                    )
                }
                _ => (
                    false,
                    "condition is not supported by the process adapter".into(),
                ),
            };
            checks.push(VerificationCheck {
                condition: condition.clone(),
                passed,
                message,
            });
        }
        Ok(checks)
    }

    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError> {
        let _ = self.decode_stage(effect, staged)?;
        Ok(AdapterRecovery {
            restored: false,
            details: json!({
                "action": "none",
                "reason": "arbitrary process effects are honestly irreversible"
            }),
        })
    }
}

#[derive(Clone, Debug)]
struct CanonicalProcessRule {
    executable: PathBuf,
    argument_sets: Vec<Vec<String>>,
    workdirs: Vec<PathBuf>,
    environment_keys: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct ProcessSpec {
    executable: PathBuf,
    arguments: Vec<String>,
    workdir: PathBuf,
    environment: Vec<ProcessEnvironment>,
}

#[derive(Clone, Debug)]
struct ProcessEnvironment {
    name: String,
    provider: String,
    key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessStage {
    spec_digest: String,
    executable_digest: String,
}

#[derive(Default)]
struct OutputCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    total: usize,
    exceeded: bool,
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

async fn drain_output<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    capture: Arc<Mutex<OutputCapture>>,
    stream: OutputStream,
    limit: usize,
) -> std::io::Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        let mut capture = capture.lock().await;
        let remaining = limit.saturating_sub(capture.total);
        let stored = remaining.min(read);
        let target = match stream {
            OutputStream::Stdout => &mut capture.stdout,
            OutputStream::Stderr => &mut capture.stderr,
        };
        target.extend_from_slice(&buffer[..stored]);
        capture.total = capture.total.saturating_add(read);
        capture.exceeded |= read > remaining;
    }
}

fn canonical_rule(
    rule: &ProcessRule,
    allow_shell_executables: bool,
) -> Result<CanonicalProcessRule, AdapterError> {
    let executable = std::fs::canonicalize(&rule.executable).map_err(AdapterError::Process)?;
    if !allow_shell_executables && is_common_shell(&executable) {
        return Err(AdapterError::Policy(
            "common shell executable is disabled by process policy".into(),
        ));
    }
    if rule.argument_sets.is_empty() || rule.workdirs.is_empty() {
        return Err(AdapterError::Policy(
            "process rule requires exact argv and workdir allowlists".into(),
        ));
    }
    let workdirs = rule
        .workdirs
        .iter()
        .map(|path| std::fs::canonicalize(path).map_err(AdapterError::Process))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalProcessRule {
        executable,
        argument_sets: rule.argument_sets.clone(),
        workdirs,
        environment_keys: rule.environment_keys.clone(),
    })
}

fn is_common_shell(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "sh" | "bash"
                    | "zsh"
                    | "fish"
                    | "dash"
                    | "cmd"
                    | "cmd.exe"
                    | "powershell"
                    | "powershell.exe"
                    | "pwsh"
                    | "pwsh.exe"
            )
        })
}

fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && !name.as_bytes()[0].is_ascii_digit()
}

fn process_preview(spec: &ProcessSpec) -> Preview {
    Preview::Process {
        executable: spec.executable.to_string_lossy().into_owned(),
        args: spec.arguments.clone(),
        workdir: spec.workdir.to_string_lossy().into_owned(),
        environment_keys: spec
            .environment
            .iter()
            .map(|value| value.name.clone())
            .collect(),
    }
}

fn process_spec_digest(spec: &ProcessSpec) -> Result<String, AdapterError> {
    veyra_protocol::canonical_digest(&json!({
        "executable": spec.executable.to_string_lossy(),
        "arguments": spec.arguments,
        "workdir": spec.workdir.to_string_lossy(),
        "environment": spec.environment.iter().map(|value| json!({
            "name": value.name,
            "provider": value.provider,
            "key": value.key,
        })).collect::<Vec<_>>(),
    }))
    .map_err(AdapterError::Canonical)
}

fn hash_file(path: &Path, limit: usize) -> Result<String, AdapterError> {
    let metadata = std::fs::metadata(path).map_err(AdapterError::Process)?;
    if !metadata.is_file() || metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(AdapterError::Policy(
            "process executable is not a bounded regular file".into(),
        ));
    }
    let mut file = std::fs::File::open(path).map_err(AdapterError::Process)?;
    let mut content = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit));
    file.read_to_end(&mut content)
        .map_err(AdapterError::Process)?;
    Ok(sha256(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_is_disabled_by_default_configuration() {
        let adapter = ProcessAdapter::new(ProcessAdapterConfig {
            enabled: false,
            rules: vec![],
            maximum_output_bytes: 1024,
            maximum_timeout_ms: 1000,
            allow_shell_executables: false,
        })
        .unwrap();
        assert!(!adapter.config.enabled);
    }

    #[test]
    fn environment_names_are_narrow() {
        assert!(valid_environment_name("SERVICE_TOKEN"));
        assert!(!valid_environment_name("service_token"));
        assert!(!valid_environment_name("1TOKEN"));
        assert!(!valid_environment_name("A=B"));
    }

    #[test]
    fn common_shell_names_are_detected() {
        assert!(is_common_shell(Path::new("C:/Windows/System32/cmd.exe")));
        assert!(is_common_shell(Path::new("/bin/bash")));
        assert!(!is_common_shell(Path::new("/usr/bin/git")));
    }
}
