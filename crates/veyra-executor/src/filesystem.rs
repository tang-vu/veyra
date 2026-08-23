//! Capability-confined filesystem adapter with durable staging and verified rollback.

use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use similar::TextDiff;
use veyra_protocol::{Condition, Effect, Preview, ResourceScope, Reversibility, VerificationCheck};

use crate::{
    AdapterContext, AdapterError, AdapterPreflight, AdapterRecovery, AdapterResult, EffectAdapter,
    StagedEffect,
    util::{no_secret_inputs, public_string, sha256},
};

const INTERNAL_DIRECTORY: &str = ".veyra";
const STAGING_DIRECTORY: &str = ".veyra/staging";

/// Filesystem adapter bounds and workspace identity.
#[derive(Clone, Debug)]
pub struct FilesystemConfig {
    /// Name used in protocol resource scopes.
    pub workspace_name: String,
    /// Trusted ambient path opened once as a capability directory.
    pub root: PathBuf,
    /// Maximum file size read, previewed, staged, or returned.
    pub maximum_file_bytes: usize,
    /// Maximum UTF-8 diff bytes placed in approval content.
    pub maximum_diff_bytes: usize,
}

/// Sandboxed filesystem adapter.
#[derive(Clone)]
pub struct FilesystemAdapter {
    config: FilesystemConfig,
    directory: Arc<Dir>,
}

impl std::fmt::Debug for FilesystemAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FilesystemAdapter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl FilesystemAdapter {
    /// Open a trusted workspace root and initialize its protected staging directory.
    ///
    /// Workspace operations use `cap-std` directory capabilities, so `..` and symlink targets
    /// outside the opened root cannot recover ambient filesystem authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when the root cannot be created/opened or the internal staging
    /// path is a symlink or non-directory.
    pub fn new(config: FilesystemConfig) -> Result<Self, AdapterError> {
        if config.workspace_name.trim().is_empty()
            || config.maximum_file_bytes == 0
            || config.maximum_diff_bytes == 0
        {
            return Err(AdapterError::InvalidEffect(
                "filesystem configuration has an empty name or size limit".into(),
            ));
        }
        std::fs::create_dir_all(&config.root).map_err(|source| AdapterError::Filesystem {
            operation: "create workspace root",
            path: "<workspace>".into(),
            source,
        })?;
        let directory =
            Dir::open_ambient_dir(&config.root, ambient_authority()).map_err(|source| {
                AdapterError::Filesystem {
                    operation: "open workspace root",
                    path: "<workspace>".into(),
                    source,
                }
            })?;
        ensure_internal_directory(&directory)?;
        Ok(Self {
            config,
            directory: Arc::new(directory),
        })
    }

    fn paths(&self, effect: &Effect) -> Result<Vec<PathBuf>, AdapterError> {
        let (workspace, paths) = match &effect.resource {
            ResourceScope::Filesystem { workspace, path } => (workspace, vec![path.as_str()]),
            ResourceScope::FilesystemSet { workspace, paths } => {
                (workspace, paths.iter().map(String::as_str).collect())
            }
            _ => {
                return Err(AdapterError::InvalidEffect(
                    "filesystem effect has a non-filesystem resource".into(),
                ));
            }
        };
        if workspace != &self.config.workspace_name {
            return Err(AdapterError::Containment(
                "effect names a different workspace".into(),
            ));
        }
        if paths.is_empty() {
            return Err(AdapterError::InvalidEffect(
                "filesystem resource contains no paths".into(),
            ));
        }
        paths.into_iter().map(normalized_relative_path).collect()
    }

    fn inspect(&self, effect: &Effect) -> Result<FsObservation, AdapterError> {
        self.validate(effect)?;
        let paths = self.paths(effect)?;
        match effect.operation.as_str() {
            "read" => {
                let content =
                    read_regular_file(&self.directory, &paths[0], self.config.maximum_file_bytes)?;
                let digest = sha256(&content);
                Ok(FsObservation {
                    operation: FsOperation::Read,
                    source: display_relative(&paths[0]),
                    destination: None,
                    before_digest: Some(digest.clone()),
                    after_digest: Some(digest),
                    before: Some(content),
                    after: None,
                })
            }
            "create" => {
                require_absent(&self.directory, &paths[0])?;
                require_existing_parent(&self.directory, &paths[0])?;
                let content = effect_content(effect, self.config.maximum_file_bytes)?;
                Ok(FsObservation {
                    operation: FsOperation::Create,
                    source: display_relative(&paths[0]),
                    destination: None,
                    before_digest: None,
                    after_digest: Some(sha256(&content)),
                    before: None,
                    after: Some(content),
                })
            }
            "patch" => {
                let before =
                    read_regular_file(&self.directory, &paths[0], self.config.maximum_file_bytes)?;
                let after = effect_content(effect, self.config.maximum_file_bytes)?;
                Ok(FsObservation {
                    operation: FsOperation::Patch,
                    source: display_relative(&paths[0]),
                    destination: None,
                    before_digest: Some(sha256(&before)),
                    after_digest: Some(sha256(&after)),
                    before: Some(before),
                    after: Some(after),
                })
            }
            "move" => {
                let source =
                    read_regular_file(&self.directory, &paths[0], self.config.maximum_file_bytes)?;
                require_absent(&self.directory, &paths[1])?;
                require_existing_parent(&self.directory, &paths[1])?;
                let digest = sha256(&source);
                Ok(FsObservation {
                    operation: FsOperation::Move,
                    source: display_relative(&paths[0]),
                    destination: Some(display_relative(&paths[1])),
                    before_digest: Some(digest.clone()),
                    after_digest: Some(digest),
                    before: None,
                    after: None,
                })
            }
            "delete" => {
                let before =
                    read_regular_file(&self.directory, &paths[0], self.config.maximum_file_bytes)?;
                Ok(FsObservation {
                    operation: FsOperation::Delete,
                    source: display_relative(&paths[0]),
                    destination: None,
                    before_digest: Some(sha256(&before)),
                    after_digest: None,
                    before: Some(before),
                    after: None,
                })
            }
            _ => unreachable!("validate rejects unknown operations"),
        }
    }

    fn preview(&self, observation: &FsObservation) -> Preview {
        let path = observation.destination.as_ref().map_or_else(
            || observation.source.clone(),
            |destination| format!("{} -> {destination}", observation.source),
        );
        let diff = match (&observation.before, &observation.after) {
            (Some(before), Some(after)) => bounded_diff(
                before,
                after,
                &observation.source,
                self.config.maximum_diff_bytes,
            ),
            (None, Some(after)) => {
                bounded_diff(&[], after, "/dev/null", self.config.maximum_diff_bytes)
            }
            (Some(before), None) if observation.operation == FsOperation::Delete => bounded_diff(
                before,
                &[],
                &observation.source,
                self.config.maximum_diff_bytes,
            ),
            _ => None,
        };
        Preview::Filesystem {
            operation: observation.operation.name().into(),
            path,
            before_sha256: observation.before_digest.clone(),
            after_sha256: observation.after_digest.clone(),
            unified_diff: diff,
        }
    }

    fn decode_stage(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
    ) -> Result<FsStage, AdapterError> {
        if staged.adapter != self.name() || staged.effect_id != effect.id {
            return Err(AdapterError::InvalidStage(
                "adapter or effect binding mismatch".into(),
            ));
        }
        let digest = effect.content_digest().map_err(AdapterError::Canonical)?;
        if staged.effect_digest != digest {
            return Err(AdapterError::InvalidStage(
                "effect content changed after staging".into(),
            ));
        }
        serde_json::from_value(staged.data.clone()).map_err(AdapterError::Serialization)
    }
}

#[async_trait]
impl EffectAdapter for FilesystemAdapter {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn validate(&self, effect: &Effect) -> Result<(), AdapterError> {
        if effect.adapter != self.name() {
            return Err(AdapterError::InvalidEffect(
                "adapter field is not `filesystem`".into(),
            ));
        }
        no_secret_inputs(&effect.inputs)?;
        let paths = self.paths(effect)?;
        match effect.operation.as_str() {
            "read" | "create" | "patch" | "delete" if paths.len() == 1 => {}
            "move" if paths.len() == 2 && paths[0] != paths[1] => {}
            "read" | "create" | "patch" | "move" | "delete" => {
                return Err(AdapterError::InvalidEffect(
                    "operation has the wrong number of exact resource paths".into(),
                ));
            }
            operation => {
                return Err(AdapterError::UnsupportedOperation {
                    adapter: self.name().into(),
                    operation: operation.into(),
                });
            }
        }
        if effect.reversibility != Reversibility::Reversible {
            return Err(AdapterError::InvalidEffect(
                "built-in file operations must declare `reversible`".into(),
            ));
        }
        if matches!(effect.operation.as_str(), "create" | "patch") {
            let _ = effect_content(effect, self.config.maximum_file_bytes)?;
        }
        Ok(())
    }

    async fn preflight(
        &self,
        effect: &Effect,
        _context: &AdapterContext,
    ) -> Result<AdapterPreflight, AdapterError> {
        let observation = self.inspect(effect)?;
        Ok(AdapterPreflight {
            preview: self.preview(&observation),
            observations: observation.safe_observations(),
        })
    }

    async fn stage(
        &self,
        effect: &Effect,
        context: &AdapterContext,
    ) -> Result<StagedEffect, AdapterError> {
        if matches!(effect.preview, Preview::Pending) {
            return Err(AdapterError::InvalidEffect(
                "filesystem effect must contain its preflight preview before staging".into(),
            ));
        }
        let observation = self.inspect(effect)?;
        if self.preview(&observation) != effect.preview {
            return Err(AdapterError::Toctou(
                "filesystem preview no longer matches current state".into(),
            ));
        }
        let stage_directory = stage_directory(context.transaction_id, effect.id);
        create_unique_stage_directory(&self.directory, &stage_directory)?;
        if let Some(after) = &observation.after {
            write_new(&self.directory, &stage_directory.join("prepared"), after)?;
        }
        let stage = FsStage {
            operation: observation.operation,
            source: observation.source,
            destination: observation.destination,
            before_digest: observation.before_digest,
            after_digest: observation.after_digest,
            stage_directory: display_relative(&stage_directory),
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
        _context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        let stage = self.decode_stage(effect, staged)?;
        let source = normalized_relative_path(&stage.source)?;
        let stage_directory = normalized_internal_path(&stage.stage_directory)?;
        match stage.operation {
            FsOperation::Read => {
                let content =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&content, stage.before_digest.as_deref(), "read source")?;
                let text = String::from_utf8(content).map_err(|_| {
                    AdapterError::InvalidEffect("read currently requires UTF-8 content".into())
                })?;
                Ok(AdapterResult {
                    outcome: "read".into(),
                    data: json!({"path": stage.source, "content": text}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Create => {
                require_absent(&self.directory, &source)?;
                require_existing_parent(&self.directory, &source)?;
                let prepared = stage_directory.join("prepared");
                self.directory
                    .rename(&prepared, &self.directory, &source)
                    .map_err(|error| fs_error("commit staged create", &source, error))?;
                Ok(AdapterResult {
                    outcome: "created".into(),
                    data: json!({"path": stage.source}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Patch => {
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.before_digest.as_deref(), "patch source")?;
                let displaced = stage_directory.join("displaced");
                self.directory
                    .rename(&source, &self.directory, &displaced)
                    .map_err(|error| fs_error("stage current patch target", &source, error))?;
                let prepared = stage_directory.join("prepared");
                if let Err(error) = self.directory.rename(&prepared, &self.directory, &source) {
                    let _ = self.directory.rename(&displaced, &self.directory, &source);
                    return Err(fs_error("commit staged patch", &source, error));
                }
                Ok(AdapterResult {
                    outcome: "patched".into(),
                    data: json!({"path": stage.source}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Move => {
                let destination = stage
                    .destination
                    .as_deref()
                    .ok_or_else(|| AdapterError::InvalidStage("move has no destination".into()))?;
                let destination_path = normalized_relative_path(destination)?;
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.before_digest.as_deref(), "move source")?;
                require_absent(&self.directory, &destination_path)?;
                require_existing_parent(&self.directory, &destination_path)?;
                self.directory
                    .rename(&source, &self.directory, &destination_path)
                    .map_err(|error| fs_error("move file", &source, error))?;
                Ok(AdapterResult {
                    outcome: "moved".into(),
                    data: json!({"from": stage.source, "to": destination}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Delete => {
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.before_digest.as_deref(), "delete source")?;
                let deleted = stage_directory.join("deleted");
                self.directory
                    .rename(&source, &self.directory, &deleted)
                    .map_err(|error| fs_error("stage deleted file", &source, error))?;
                Ok(AdapterResult {
                    outcome: "deleted".into(),
                    data: json!({"path": stage.source}),
                    post_state_digest: None,
                })
            }
        }
    }

    async fn verify(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        result: &AdapterResult,
        _context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError> {
        let stage = self.decode_stage(effect, staged)?;
        let mut checks = Vec::with_capacity(effect.expected_postconditions.len() + 1);
        let intrinsic = self.intrinsic_check(&stage)?;
        checks.push(VerificationCheck {
            condition: Condition::Custom {
                name: "veyra.filesystem.intrinsic/v1".into(),
                parameters: json!({"operation": stage.operation.name()}),
            },
            passed: intrinsic.0,
            message: intrinsic.1,
        });
        for condition in &effect.expected_postconditions {
            checks.push(self.check_condition(condition, result)?);
        }
        Ok(checks)
    }

    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        _context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError> {
        let stage = self.decode_stage(effect, staged)?;
        let source = normalized_relative_path(&stage.source)?;
        let stage_directory = normalized_internal_path(&stage.stage_directory)?;
        match stage.operation {
            FsOperation::Read => Ok(AdapterRecovery {
                restored: true,
                details: json!({"operation": "read", "action": "none"}),
            }),
            FsOperation::Create => {
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.after_digest.as_deref(), "created file")?;
                self.directory
                    .remove_file(&source)
                    .map_err(|error| fs_error("remove created file", &source, error))?;
                Ok(restored("removed created file"))
            }
            FsOperation::Patch => {
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.after_digest.as_deref(), "patched file")?;
                let rolled_forward = stage_directory.join("rolled-forward");
                self.directory
                    .rename(&source, &self.directory, &rolled_forward)
                    .map_err(|error| fs_error("preserve patched file", &source, error))?;
                let displaced = stage_directory.join("displaced");
                if let Err(error) = self.directory.rename(&displaced, &self.directory, &source) {
                    let _ = self
                        .directory
                        .rename(&rolled_forward, &self.directory, &source);
                    return Err(fs_error("restore original file", &source, error));
                }
                Ok(restored("restored original file"))
            }
            FsOperation::Move => {
                let destination =
                    normalized_relative_path(stage.destination.as_deref().ok_or_else(|| {
                        AdapterError::InvalidStage("move has no destination".into())
                    })?)?;
                require_absent(&self.directory, &source)?;
                let current = read_regular_file(
                    &self.directory,
                    &destination,
                    self.config.maximum_file_bytes,
                )?;
                require_digest(&current, stage.after_digest.as_deref(), "moved file")?;
                self.directory
                    .rename(&destination, &self.directory, &source)
                    .map_err(|error| fs_error("restore moved file", &source, error))?;
                Ok(restored("moved file back to its original path"))
            }
            FsOperation::Delete => {
                require_absent(&self.directory, &source)?;
                let deleted = stage_directory.join("deleted");
                let deleted_content =
                    read_regular_file(&self.directory, &deleted, self.config.maximum_file_bytes)?;
                require_digest(
                    &deleted_content,
                    stage.before_digest.as_deref(),
                    "staged deletion",
                )?;
                self.directory
                    .rename(&deleted, &self.directory, &source)
                    .map_err(|error| fs_error("restore deleted file", &source, error))?;
                Ok(restored("restored deleted file"))
            }
        }
    }
}

impl FilesystemAdapter {
    fn intrinsic_check(&self, stage: &FsStage) -> Result<(bool, String), AdapterError> {
        let source = normalized_relative_path(&stage.source)?;
        match stage.operation {
            FsOperation::Read | FsOperation::Create | FsOperation::Patch => {
                let content =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                let actual = sha256(&content);
                Ok((
                    stage.after_digest.as_deref() == Some(actual.as_str()),
                    "primary file digest checked".into(),
                ))
            }
            FsOperation::Move => {
                let destination =
                    normalized_relative_path(stage.destination.as_deref().ok_or_else(|| {
                        AdapterError::InvalidStage("move has no destination".into())
                    })?)?;
                let source_absent = !self
                    .directory
                    .try_exists(&source)
                    .map_err(|error| fs_error("check moved source", &source, error))?;
                let destination_content = read_regular_file(
                    &self.directory,
                    &destination,
                    self.config.maximum_file_bytes,
                )?;
                let actual = sha256(&destination_content);
                Ok((
                    source_absent && stage.after_digest.as_deref() == Some(actual.as_str()),
                    "move source absence and destination digest checked".into(),
                ))
            }
            FsOperation::Delete => Ok((
                !self
                    .directory
                    .try_exists(&source)
                    .map_err(|error| fs_error("check deleted path", &source, error))?,
                "deleted path absence checked".into(),
            )),
        }
    }

    fn check_condition(
        &self,
        condition: &Condition,
        result: &AdapterResult,
    ) -> Result<VerificationCheck, AdapterError> {
        let (passed, message) = match condition {
            Condition::FileExists { path, expected } => {
                let path = normalized_relative_path(path)?;
                let actual = self
                    .directory
                    .try_exists(&path)
                    .map_err(|error| fs_error("check file existence", &path, error))?;
                (actual == *expected, format!("existence was {actual}"))
            }
            Condition::FileSha256 { path, digest } => {
                let path = normalized_relative_path(path)?;
                let content =
                    read_regular_file(&self.directory, &path, self.config.maximum_file_bytes)?;
                let actual = sha256(&content);
                (actual == *digest, format!("observed sha256 {actual}"))
            }
            Condition::OutputSha256 { digest } => (
                result.post_state_digest.as_deref() == Some(digest),
                "adapter output digest checked".into(),
            ),
            Condition::HttpStatus { .. } | Condition::Custom { .. } => (
                false,
                "condition is not supported by the filesystem adapter".into(),
            ),
        };
        Ok(VerificationCheck {
            condition: condition.clone(),
            passed,
            message,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FsOperation {
    Read,
    Create,
    Patch,
    Move,
    Delete,
}

impl FsOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Patch => "patch",
            Self::Move => "move",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug)]
struct FsObservation {
    operation: FsOperation,
    source: String,
    destination: Option<String>,
    before_digest: Option<String>,
    after_digest: Option<String>,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

impl FsObservation {
    fn safe_observations(&self) -> Value {
        json!({
            "operation": self.operation.name(),
            "source": self.source,
            "destination": self.destination,
            "before_sha256": self.before_digest,
            "after_sha256": self.after_digest,
            "before_bytes": self.before.as_ref().map(Vec::len),
            "after_bytes": self.after.as_ref().map(Vec::len),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FsStage {
    operation: FsOperation,
    source: String,
    destination: Option<String>,
    before_digest: Option<String>,
    after_digest: Option<String>,
    stage_directory: String,
}

fn ensure_internal_directory(directory: &Dir) -> Result<(), AdapterError> {
    if let Ok(metadata) = directory.symlink_metadata(INTERNAL_DIRECTORY)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(AdapterError::Containment(
            "reserved internal workspace path is not a real directory".into(),
        ));
    }
    directory
        .create_dir_all(STAGING_DIRECTORY)
        .map_err(|source| AdapterError::Filesystem {
            operation: "create staging directory",
            path: STAGING_DIRECTORY.into(),
            source,
        })?;
    for path in [INTERNAL_DIRECTORY, STAGING_DIRECTORY] {
        let metadata =
            directory
                .symlink_metadata(path)
                .map_err(|source| AdapterError::Filesystem {
                    operation: "inspect staging directory",
                    path: path.into(),
                    source,
                })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AdapterError::Containment(
                "staging path contains a symlink or non-directory".into(),
            ));
        }
    }
    Ok(())
}

fn normalized_relative_path(value: &str) -> Result<PathBuf, AdapterError> {
    if value.is_empty() || value.contains('\\') || value.as_bytes().contains(&0) {
        return Err(AdapterError::Containment(
            "path must use non-empty forward-slash relative syntax".into(),
        ));
    }
    let path = Path::new(value);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(AdapterError::Containment(
                    "path contains an absolute, parent, or non-normal component".into(),
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty()
        || normalized
            .components()
            .next()
            .is_some_and(|component| component.as_os_str() == INTERNAL_DIRECTORY)
    {
        return Err(AdapterError::Containment(
            "path targets Veyra's reserved internal directory".into(),
        ));
    }
    Ok(normalized)
}

fn normalized_internal_path(value: &str) -> Result<PathBuf, AdapterError> {
    let path = Path::new(value);
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 3
        || parts
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || parts[0].as_os_str() != INTERNAL_DIRECTORY
        || parts[1].as_os_str() != "staging"
    {
        return Err(AdapterError::InvalidStage(
            "stage path is outside the reserved staging directory".into(),
        ));
    }
    Ok(path.to_path_buf())
}

fn reject_symlink_components(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match directory.symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AdapterError::Containment(format!(
                    "symlink component `{}` is not accepted",
                    display_relative(&current)
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(fs_error("inspect path component", &current, error)),
        }
    }
    Ok(())
}

fn require_existing_parent(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    reject_symlink_components(directory, path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    directory
        .open_dir(parent)
        .map_err(|error| fs_error("open parent directory", parent, error))?;
    Ok(())
}

fn require_absent(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    reject_symlink_components(directory, path)?;
    if directory
        .try_exists(path)
        .map_err(|error| fs_error("check path absence", path, error))?
    {
        Err(AdapterError::Precondition(format!(
            "`{}` already exists",
            display_relative(path)
        )))
    } else {
        Ok(())
    }
}

fn read_regular_file(directory: &Dir, path: &Path, limit: usize) -> Result<Vec<u8>, AdapterError> {
    reject_symlink_components(directory, path)?;
    let metadata = directory
        .symlink_metadata(path)
        .map_err(|error| fs_error("inspect regular file", path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AdapterError::Precondition(format!(
            "`{}` is not a regular file",
            display_relative(path)
        )));
    }
    if metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(AdapterError::SizeLimit {
            kind: "filesystem file",
            limit,
        });
    }
    let file = directory
        .open(path)
        .map_err(|error| fs_error("open regular file", path, error))?;
    let mut content =
        Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit).min(limit));
    file.take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut content)
        .map_err(|error| fs_error("read regular file", path, error))?;
    if content.len() > limit {
        return Err(AdapterError::SizeLimit {
            kind: "filesystem file",
            limit,
        });
    }
    Ok(content)
}

fn write_new(directory: &Dir, path: &Path, content: &[u8]) -> Result<(), AdapterError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = directory
        .open_with(path, &options)
        .map_err(|error| fs_error("create staged file", path, error))?;
    file.write_all(content)
        .map_err(|error| fs_error("write staged file", path, error))?;
    file.sync_all()
        .map_err(|error| fs_error("sync staged file", path, error))
}

fn create_unique_stage_directory(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::InvalidStage("stage directory has no parent".into()))?;
    directory
        .create_dir_all(parent)
        .map_err(|error| fs_error("create stage parent", parent, error))?;
    directory
        .create_dir(path)
        .map_err(|error| fs_error("create unique stage", path, error))
}

fn stage_directory(
    transaction_id: veyra_protocol::TransactionId,
    effect_id: veyra_protocol::EffectId,
) -> PathBuf {
    Path::new(STAGING_DIRECTORY)
        .join(transaction_id.to_string())
        .join(effect_id.to_string())
}

fn effect_content(effect: &Effect, limit: usize) -> Result<Vec<u8>, AdapterError> {
    let content = public_string(&effect.inputs, "content")?
        .as_bytes()
        .to_vec();
    if content.len() > limit {
        return Err(AdapterError::SizeLimit {
            kind: "filesystem input",
            limit,
        });
    }
    Ok(content)
}

fn require_digest(
    content: &[u8],
    expected: Option<&str>,
    subject: &str,
) -> Result<(), AdapterError> {
    let actual = sha256(content);
    if expected == Some(actual.as_str()) {
        Ok(())
    } else {
        Err(AdapterError::Toctou(format!(
            "{subject} digest no longer matches staged evidence"
        )))
    }
}

fn bounded_diff(before: &[u8], after: &[u8], path: &str, limit: usize) -> Option<String> {
    let before = std::str::from_utf8(before).ok()?;
    let after = std::str::from_utf8(after).ok()?;
    let mut diff = TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(path, path)
        .to_string();
    if diff.len() > limit {
        diff.truncate(limit);
        diff.push_str("\n... diff truncated by Veyra ...\n");
    }
    Some(diff)
}

fn display_relative(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn fs_error(operation: &'static str, path: &Path, source: std::io::Error) -> AdapterError {
    AdapterError::Filesystem {
        operation,
        path: display_relative(path),
        source,
    }
}

fn restored(action: &str) -> AdapterRecovery {
    AdapterRecovery {
        restored: true,
        details: json!({"action": action}),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use tempfile::TempDir;
    use veyra_protocol::{
        CapabilityRequirement, CausalParent, EffectId, IntentId, PROTOCOL_VERSION, PlanId,
        PrincipalId, RetryPolicy, RiskLevel, StepId, public,
    };

    use super::*;
    use crate::DenySecretResolver;

    fn adapter() -> (TempDir, FilesystemAdapter) {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("notes")).unwrap();
        let adapter = FilesystemAdapter::new(FilesystemConfig {
            workspace_name: "demo".into(),
            root: temp.path().to_path_buf(),
            maximum_file_bytes: 1024 * 1024,
            maximum_diff_bytes: 64 * 1024,
        })
        .unwrap();
        (temp, adapter)
    }

    fn context() -> AdapterContext {
        AdapterContext {
            transaction_id: veyra_protocol::TransactionId::new(),
            secrets: Arc::new(DenySecretResolver),
        }
    }

    fn effect(operation: &str, paths: &[&str], content: Option<&str>) -> Effect {
        let resource = if paths.len() == 1 {
            ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: paths[0].into(),
            }
        } else {
            ResourceScope::FilesystemSet {
                workspace: "demo".into(),
                paths: paths.iter().map(|value| (*value).to_owned()).collect(),
            }
        };
        let mut inputs = BTreeMap::new();
        if let Some(content) = content {
            inputs.insert("content".into(), public(content));
        }
        Effect {
            schema_version: PROTOCOL_VERSION.into(),
            id: EffectId::new(),
            causal_parent: CausalParent {
                intent_id: IntentId::new(),
                plan_id: PlanId::new(),
                step_id: StepId::new(),
                effect_id: None,
            },
            principal_id: PrincipalId::new(),
            adapter: "filesystem".into(),
            operation: operation.into(),
            inputs,
            resource: resource.clone(),
            preconditions: vec![],
            expected_postconditions: vec![],
            risk: RiskLevel::Medium,
            reversibility: Reversibility::Reversible,
            preview: Preview::Pending,
            idempotency_key: format!("{operation}-key"),
            timeout_ms: 1_000,
            retry: RetryPolicy {
                max_attempts: 1,
                backoff_ms: 0,
                retryable_errors: vec![],
            },
            required_capabilities: vec![CapabilityRequirement {
                adapter: "filesystem".into(),
                operation: operation.into(),
                resource,
                constraints: BTreeMap::new(),
            }],
            inverse: None,
        }
    }

    async fn preflight_and_stage(
        adapter: &FilesystemAdapter,
        mut effect: Effect,
        context: &AdapterContext,
    ) -> (Effect, StagedEffect) {
        effect.preview = adapter.preflight(&effect, context).await.unwrap().preview;
        let staged = adapter.stage(&effect, context).await.unwrap();
        (effect, staged)
    }

    #[tokio::test]
    async fn create_verify_and_rollback_round_trip() {
        let (temp, adapter) = adapter();
        let context = context();
        let mut effect = effect("create", &["notes/hello.txt"], Some("hello\n"));
        effect.expected_postconditions = vec![Condition::FileSha256 {
            path: "notes/hello.txt".into(),
            digest: sha256(b"hello\n"),
        }];
        let (effect, staged) = preflight_and_stage(&adapter, effect, &context).await;
        assert!(!temp.path().join("notes/hello.txt").exists());
        let result = adapter.execute(&effect, &staged, &context).await.unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("notes/hello.txt")).unwrap(),
            b"hello\n"
        );
        assert!(
            adapter
                .verify(&effect, &staged, &result, &context)
                .await
                .unwrap()
                .iter()
                .all(|check| check.passed)
        );
        assert!(
            adapter
                .rollback(&effect, &staged, &context)
                .await
                .unwrap()
                .restored
        );
        assert!(!temp.path().join("notes/hello.txt").exists());
    }

    #[tokio::test]
    async fn mutation_after_preview_is_rejected_before_stage() {
        let (temp, adapter) = adapter();
        std::fs::write(temp.path().join("notes/file.txt"), "one").unwrap();
        let context = context();
        let mut effect = effect("patch", &["notes/file.txt"], Some("two"));
        effect.preview = adapter.preflight(&effect, &context).await.unwrap().preview;
        std::fs::write(temp.path().join("notes/file.txt"), "attacker").unwrap();
        assert!(matches!(
            adapter.stage(&effect, &context).await,
            Err(AdapterError::Toctou(_))
        ));
    }

    #[tokio::test]
    async fn rollback_refuses_to_clobber_post_execution_change() {
        let (temp, adapter) = adapter();
        let context = context();
        let effect = effect("create", &["notes/file.txt"], Some("created"));
        let (effect, staged) = preflight_and_stage(&adapter, effect, &context).await;
        adapter.execute(&effect, &staged, &context).await.unwrap();
        std::fs::write(temp.path().join("notes/file.txt"), "changed later").unwrap();
        assert!(matches!(
            adapter.rollback(&effect, &staged, &context).await,
            Err(AdapterError::Toctou(_))
        ));
        assert_eq!(
            std::fs::read_to_string(temp.path().join("notes/file.txt")).unwrap(),
            "changed later"
        );
    }

    #[test]
    fn traversal_and_reserved_paths_are_rejected() {
        let (_temp, adapter) = adapter();
        for path in [
            "../outside",
            "/absolute",
            ".veyra/journal.db",
            "safe\\..\\outside",
        ] {
            assert!(adapter.paths(&effect("read", &[path], None)).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let (temp, adapter) = adapter();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("secret"), "do not read").unwrap();
        symlink(outside.path(), temp.path().join("link")).unwrap();
        let context = context();
        assert!(matches!(
            adapter
                .preflight(&effect("read", &["link/secret"], None), &context)
                .await,
            Err(AdapterError::Containment(_))
        ));
    }
}
