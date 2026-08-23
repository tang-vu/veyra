//! Capability-confined filesystem adapter with durable staging and verified rollback.

use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
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
    util::{no_secret_inputs, no_unsupported_capability_constraints, public_string, sha256},
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
        context: &AdapterContext,
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
        let stage: FsStage =
            serde_json::from_value(staged.data.clone()).map_err(AdapterError::Serialization)?;
        let paths = self.paths(effect)?;
        let expected_source = display_relative(&paths[0]);
        let expected_destination = paths.get(1).map(|path| display_relative(path));
        let expected_path = expected_destination.as_ref().map_or_else(
            || expected_source.clone(),
            |destination| format!("{expected_source} -> {destination}"),
        );
        let Preview::Filesystem {
            operation,
            path,
            before_sha256,
            after_sha256,
            ..
        } = &effect.preview
        else {
            return Err(AdapterError::InvalidStage(
                "filesystem stage has no authoritative preview".into(),
            ));
        };
        let expected_stage_directory =
            display_relative(&stage_directory(context.transaction_id, effect.id));
        if operation != stage.operation.name()
            || path != &expected_path
            || stage.source != expected_source
            || stage.destination != expected_destination
            || &stage.before_digest != before_sha256
            || &stage.after_digest != after_sha256
            || stage.stage_directory != expected_stage_directory
        {
            return Err(AdapterError::InvalidStage(
                "filesystem stage details disagree with the approved effect".into(),
            ));
        }
        Ok(stage)
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
        no_unsupported_capability_constraints(effect, &[])?;
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

    #[allow(clippy::too_many_lines)]
    async fn execute(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterResult, AdapterError> {
        let stage = self.decode_stage(effect, staged, context)?;
        let source = normalized_relative_path(&stage.source)?;
        let stage_directory = normalized_internal_path(&stage.stage_directory)?;
        match stage.operation {
            FsOperation::Read => {
                let file_bytes =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&file_bytes, stage.before_digest.as_deref(), "read source")?;
                let text = String::from_utf8(file_bytes).map_err(|_| {
                    AdapterError::InvalidEffect("read currently requires UTF-8 content".into())
                })?;
                Ok(AdapterResult {
                    outcome: "read".into(),
                    data: json!({"path": stage.source, "content": text}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Create => {
                require_existing_parent(&self.directory, &source)?;
                let prepared = stage_directory.join("prepared");
                verify_captured_file(
                    &self.directory,
                    &prepared,
                    stage.after_digest.as_deref(),
                    "prepared create content",
                    self.config.maximum_file_bytes,
                )?;
                move_noreplace_anchored(
                    &self.directory,
                    &prepared,
                    &source,
                    "commit staged create",
                )?;
                Ok(AdapterResult {
                    outcome: "created".into(),
                    data: json!({"path": stage.source}),
                    post_state_digest: stage.after_digest,
                })
            }
            FsOperation::Patch => {
                let prepared = stage_directory.join("prepared");
                verify_captured_file(
                    &self.directory,
                    &prepared,
                    stage.after_digest.as_deref(),
                    "prepared patch content",
                    self.config.maximum_file_bytes,
                )?;
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.before_digest.as_deref(), "patch source")?;
                let displaced = stage_directory.join("displaced");
                move_noreplace_anchored(
                    &self.directory,
                    &source,
                    &displaced,
                    "stage current patch target",
                )?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &displaced,
                    stage.before_digest.as_deref(),
                    "captured patch source",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &displaced,
                        &source,
                        "restore changed patch source",
                    );
                    return Err(error);
                }
                if let Err(error) = move_noreplace_anchored(
                    &self.directory,
                    &prepared,
                    &source,
                    "commit staged patch",
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &displaced,
                        &source,
                        "restore failed patch",
                    );
                    return Err(error);
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
                require_existing_parent(&self.directory, &destination_path)?;
                let moving = stage_directory.join("moving");
                move_noreplace_anchored(&self.directory, &source, &moving, "capture move source")?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &moving,
                    stage.before_digest.as_deref(),
                    "captured move source",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &moving,
                        &source,
                        "restore changed move source",
                    );
                    return Err(error);
                }
                if let Err(error) = move_noreplace_anchored(
                    &self.directory,
                    &moving,
                    &destination_path,
                    "move file",
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &moving,
                        &source,
                        "restore failed move",
                    );
                    return Err(error);
                }
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
                move_noreplace_anchored(&self.directory, &source, &deleted, "stage deleted file")?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &deleted,
                    stage.before_digest.as_deref(),
                    "captured delete source",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &deleted,
                        &source,
                        "restore changed delete source",
                    );
                    return Err(error);
                }
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
        context: &AdapterContext,
    ) -> Result<Vec<VerificationCheck>, AdapterError> {
        let stage = self.decode_stage(effect, staged, context)?;
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

    #[allow(clippy::too_many_lines)]
    async fn rollback(
        &self,
        effect: &Effect,
        staged: &StagedEffect,
        context: &AdapterContext,
    ) -> Result<AdapterRecovery, AdapterError> {
        let stage = self.decode_stage(effect, staged, context)?;
        let source = normalized_relative_path(&stage.source)?;
        let stage_directory = normalized_internal_path(&stage.stage_directory)?;
        match stage.operation {
            FsOperation::Read => Ok(AdapterRecovery {
                restored: true,
                details: json!({"operation": "read", "action": "none"}),
            }),
            FsOperation::Create => {
                if !path_exists_nofollow(&self.directory, &source)? {
                    return Ok(restored("created file was already absent"));
                }
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                require_digest(&current, stage.after_digest.as_deref(), "created file")?;
                let rolled_back = stage_directory.join("rolled-back-create");
                move_noreplace_anchored(
                    &self.directory,
                    &source,
                    &rolled_back,
                    "capture created file for rollback",
                )?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &rolled_back,
                    stage.after_digest.as_deref(),
                    "captured created file",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &rolled_back,
                        &source,
                        "restore changed created file",
                    );
                    return Err(error);
                }
                Ok(restored("removed created file"))
            }
            FsOperation::Patch => {
                let current =
                    read_regular_file(&self.directory, &source, self.config.maximum_file_bytes)?;
                if stage.before_digest.as_deref() == Some(sha256(&current).as_str()) {
                    return Ok(restored(
                        "patch target already matched its original content",
                    ));
                }
                require_digest(&current, stage.after_digest.as_deref(), "patched file")?;
                let rolled_forward = stage_directory.join("rolled-forward");
                move_noreplace_anchored(
                    &self.directory,
                    &source,
                    &rolled_forward,
                    "preserve patched file",
                )?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &rolled_forward,
                    stage.after_digest.as_deref(),
                    "captured patched file",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &rolled_forward,
                        &source,
                        "restore changed patched file",
                    );
                    return Err(error);
                }
                let displaced = stage_directory.join("displaced");
                if let Err(error) = move_noreplace_anchored(
                    &self.directory,
                    &displaced,
                    &source,
                    "restore original file",
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &rolled_forward,
                        &source,
                        "restore failed rollback",
                    );
                    return Err(error);
                }
                Ok(restored("restored original file"))
            }
            FsOperation::Move => {
                let destination =
                    normalized_relative_path(stage.destination.as_deref().ok_or_else(|| {
                        AdapterError::InvalidStage("move has no destination".into())
                    })?)?;
                if !path_exists_nofollow(&self.directory, &destination)? {
                    if path_exists_nofollow(&self.directory, &source)? {
                        let source_content = read_regular_file(
                            &self.directory,
                            &source,
                            self.config.maximum_file_bytes,
                        )?;
                        require_digest(
                            &source_content,
                            stage.before_digest.as_deref(),
                            "original move source",
                        )?;
                        return Ok(restored("move source was already at its original path"));
                    }
                    let moving = stage_directory.join("moving");
                    verify_captured_file(
                        &self.directory,
                        &moving,
                        stage.before_digest.as_deref(),
                        "interrupted move source",
                        self.config.maximum_file_bytes,
                    )?;
                    move_noreplace_anchored(
                        &self.directory,
                        &moving,
                        &source,
                        "restore interrupted move",
                    )?;
                    return Ok(restored("restored an interrupted move source"));
                }
                let current = read_regular_file(
                    &self.directory,
                    &destination,
                    self.config.maximum_file_bytes,
                )?;
                require_digest(&current, stage.after_digest.as_deref(), "moved file")?;
                let moving = stage_directory.join("rollback-moving");
                move_noreplace_anchored(
                    &self.directory,
                    &destination,
                    &moving,
                    "capture moved file for rollback",
                )?;
                if let Err(error) = verify_captured_file(
                    &self.directory,
                    &moving,
                    stage.after_digest.as_deref(),
                    "captured moved file",
                    self.config.maximum_file_bytes,
                ) {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &moving,
                        &destination,
                        "restore changed moved file",
                    );
                    return Err(error);
                }
                if let Err(error) =
                    move_noreplace_anchored(&self.directory, &moving, &source, "restore moved file")
                {
                    let _ = move_noreplace_anchored(
                        &self.directory,
                        &moving,
                        &destination,
                        "restore failed move rollback",
                    );
                    return Err(error);
                }
                Ok(restored("moved file back to its original path"))
            }
            FsOperation::Delete => {
                if path_exists_nofollow(&self.directory, &source)? {
                    let current = read_regular_file(
                        &self.directory,
                        &source,
                        self.config.maximum_file_bytes,
                    )?;
                    require_digest(
                        &current,
                        stage.before_digest.as_deref(),
                        "original delete source",
                    )?;
                    return Ok(restored("deleted file was already at its original path"));
                }
                let deleted = stage_directory.join("deleted");
                let deleted_content =
                    read_regular_file(&self.directory, &deleted, self.config.maximum_file_bytes)?;
                require_digest(
                    &deleted_content,
                    stage.before_digest.as_deref(),
                    "staged deletion",
                )?;
                move_noreplace_anchored(
                    &self.directory,
                    &deleted,
                    &source,
                    "restore deleted file",
                )?;
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
                let source_absent = !path_exists_nofollow(&self.directory, &source)?;
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
                !path_exists_nofollow(&self.directory, &source)?,
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
                let actual = path_exists_nofollow(&self.directory, &path)?;
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
    let _ = open_or_create_directory_nofollow(directory, Path::new(STAGING_DIRECTORY))?;
    Ok(())
}

fn normalized_relative_path(value: &str) -> Result<PathBuf, AdapterError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains(':')
        || value.as_bytes().contains(&0)
    {
        return Err(AdapterError::Containment(
            "path must use non-empty forward-slash relative syntax".into(),
        ));
    }
    let path = Path::new(value);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) if is_portable_component(value) => normalized.push(value),
            Component::Normal(_) => {
                return Err(AdapterError::Containment(
                    "path contains a reserved or platform-ambiguous component".into(),
                ));
            }
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
        || normalized.components().next().is_some_and(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(INTERNAL_DIRECTORY))
        })
    {
        return Err(AdapterError::Containment(
            "path targets Veyra's reserved internal directory".into(),
        ));
    }
    Ok(normalized)
}

fn is_portable_component(component: &std::ffi::OsStr) -> bool {
    let Some(component) = component.to_str() else {
        return false;
    };
    if component.ends_with('.') || component.ends_with(' ') {
        return false;
    }
    let stem = component.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    !matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "CLOCK$"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    ) && !(upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && matches!(upper.as_bytes()[3], b'1'..=b'9'))
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

fn require_existing_parent(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    let _ = open_parent_nofollow(directory, path)?;
    Ok(())
}

fn require_absent(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    let (parent, name) = open_parent_nofollow(directory, path)?;
    match parent.symlink_metadata(name) {
        Ok(_) => Err(AdapterError::Precondition(format!(
            "`{}` already exists",
            display_relative(path)
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fs_error("check path absence", path, error)),
    }
}

fn read_regular_file(directory: &Dir, path: &Path, limit: usize) -> Result<Vec<u8>, AdapterError> {
    let (parent, name) = open_parent_nofollow(directory, path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent
        .open_with(name, &options)
        .map_err(|error| fs_error("open regular file without following links", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| fs_error("inspect opened regular file", path, error))?;
    if !metadata.is_file() {
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
    let (parent, name) = open_parent_nofollow(directory, path)?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|error| fs_error("create staged file", path, error))?;
    file.write_all(content)
        .map_err(|error| fs_error("write staged file", path, error))?;
    file.sync_all()
        .map_err(|error| fs_error("sync staged file", path, error))
}

/// Move a regular file without ever replacing an existing destination.
///
/// The hard-link creation is the atomic no-clobber point. Staging lives below
/// the same capability root, so source and destination are on one filesystem.
/// If unlinking the source fails, both names may remain and the caller receives
/// an error for conservative recovery; an existing destination is never lost.
fn move_noreplace_anchored(
    directory: &Dir,
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> Result<(), AdapterError> {
    let (source_parent, source_name) = open_parent_nofollow(directory, source)?;
    let (destination_parent, destination_name) = open_parent_nofollow(directory, destination)?;
    let metadata = source_parent
        .symlink_metadata(source_name)
        .map_err(|error| fs_error("inspect no-replace move source", source, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterError::Precondition(format!(
            "`{}` is not a regular, non-symlink file",
            display_relative(source)
        )));
    }
    source_parent
        .hard_link(source_name, &destination_parent, destination_name)
        .map_err(|error| fs_error(operation, destination, error))?;
    source_parent
        .remove_file(source_name)
        .map_err(|error| fs_error(operation, source, error))
}

fn path_exists_nofollow(directory: &Dir, path: &Path) -> Result<bool, AdapterError> {
    let (parent, name) = match open_parent_nofollow(directory, path) {
        Ok(opened) => opened,
        Err(AdapterError::Filesystem { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(AdapterError::Containment(format!(
                "symlink component `{}` is not accepted",
                display_relative(path)
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(fs_error("check path existence", path, error)),
    }
}

fn create_unique_stage_directory(directory: &Dir, path: &Path) -> Result<(), AdapterError> {
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::InvalidStage("stage directory has no parent".into()))?;
    let parent_directory = open_or_create_directory_nofollow(directory, parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| AdapterError::InvalidStage("stage directory has no name".into()))?;
    parent_directory
        .create_dir(name)
        .map_err(|error| fs_error("create unique stage", path, error))
}

fn open_parent_nofollow<'a>(
    directory: &Dir,
    path: &'a Path,
) -> Result<(Dir, &'a std::ffi::OsStr), AdapterError> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let name = path
        .file_name()
        .ok_or_else(|| AdapterError::Containment("path has no final component".into()))?;
    Ok((open_directory_nofollow(directory, parent)?, name))
}

fn open_directory_nofollow(directory: &Dir, path: &Path) -> Result<Dir, AdapterError> {
    let mut opened = directory
        .try_clone()
        .map_err(|error| fs_error("clone capability directory", path, error))?;
    let mut traversed = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(AdapterError::Containment(
                "directory path contains a non-normal component".into(),
            ));
        };
        traversed.push(name);
        opened = opened.open_dir_nofollow(name).map_err(|error| {
            if opened
                .symlink_metadata(name)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                AdapterError::Containment(format!(
                    "symlink component `{}` is not accepted",
                    display_relative(&traversed)
                ))
            } else {
                fs_error("open directory component", &traversed, error)
            }
        })?;
    }
    Ok(opened)
}

fn open_or_create_directory_nofollow(directory: &Dir, path: &Path) -> Result<Dir, AdapterError> {
    let mut opened = directory
        .try_clone()
        .map_err(|error| fs_error("clone capability directory", path, error))?;
    let mut traversed = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(AdapterError::Containment(
                "directory path contains a non-normal component".into(),
            ));
        };
        traversed.push(name);
        match opened.open_dir_nofollow(name) {
            Ok(next) => opened = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match opened.create_dir(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(fs_error("create directory component", &traversed, error));
                    }
                }
                opened = opened.open_dir_nofollow(name).map_err(|error| {
                    fs_error("open created directory component", &traversed, error)
                })?;
            }
            Err(error) => {
                return Err(
                    if opened
                        .symlink_metadata(name)
                        .is_ok_and(|metadata| metadata.file_type().is_symlink())
                    {
                        AdapterError::Containment(format!(
                            "symlink component `{}` is not accepted",
                            display_relative(&traversed)
                        ))
                    } else {
                        fs_error("open directory component", &traversed, error)
                    },
                );
            }
        }
    }
    Ok(opened)
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

fn verify_captured_file(
    directory: &Dir,
    path: &Path,
    expected: Option<&str>,
    subject: &str,
    limit: usize,
) -> Result<(), AdapterError> {
    let content = read_regular_file(directory, path, limit)?;
    require_digest(&content, expected, subject)
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
    async fn rollback_recognizes_staged_but_unexecuted_filesystem_effects() {
        let (temp, adapter) = adapter();
        let context = context();

        let (create, create_stage) = preflight_and_stage(
            &adapter,
            effect("create", &["notes/new.txt"], Some("new")),
            &context,
        )
        .await;
        assert!(
            adapter
                .rollback(&create, &create_stage, &context)
                .await
                .unwrap()
                .restored
        );

        std::fs::write(temp.path().join("notes/patch.txt"), "before").unwrap();
        let (patch, patch_stage) = preflight_and_stage(
            &adapter,
            effect("patch", &["notes/patch.txt"], Some("after")),
            &context,
        )
        .await;
        assert!(
            adapter
                .rollback(&patch, &patch_stage, &context)
                .await
                .unwrap()
                .restored
        );

        std::fs::write(temp.path().join("notes/source.txt"), "move").unwrap();
        let (moving, move_stage) = preflight_and_stage(
            &adapter,
            effect("move", &["notes/source.txt", "notes/destination.txt"], None),
            &context,
        )
        .await;
        assert!(
            adapter
                .rollback(&moving, &move_stage, &context)
                .await
                .unwrap()
                .restored
        );

        std::fs::write(temp.path().join("notes/delete.txt"), "delete").unwrap();
        let (delete, delete_stage) = preflight_and_stage(
            &adapter,
            effect("delete", &["notes/delete.txt"], None),
            &context,
        )
        .await;
        assert!(
            adapter
                .rollback(&delete, &delete_stage, &context)
                .await
                .unwrap()
                .restored
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("notes/patch.txt")).unwrap(),
            "before"
        );
        assert!(temp.path().join("notes/source.txt").exists());
        assert!(!temp.path().join("notes/destination.txt").exists());
        assert!(temp.path().join("notes/delete.txt").exists());
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
    async fn destination_created_after_staging_is_never_clobbered() {
        let (temp, adapter) = adapter();
        let context = context();
        let effect = effect("create", &["notes/file.txt"], Some("veyra"));
        let (effect, staged) = preflight_and_stage(&adapter, effect, &context).await;
        std::fs::write(temp.path().join("notes/file.txt"), "concurrent writer").unwrap();

        assert!(adapter.execute(&effect, &staged, &context).await.is_err());
        assert_eq!(
            std::fs::read_to_string(temp.path().join("notes/file.txt")).unwrap(),
            "concurrent writer"
        );
    }

    #[tokio::test]
    async fn staged_prepared_bytes_are_rechecked_before_commit() {
        let (temp, adapter) = adapter();
        let context = context();
        let effect = effect("create", &["notes/prepared.txt"], Some("approved"));
        let (effect, staged) = preflight_and_stage(&adapter, effect, &context).await;
        let details: FsStage = serde_json::from_value(staged.data.clone()).unwrap();
        std::fs::write(
            temp.path().join(details.stage_directory).join("prepared"),
            "tampered",
        )
        .unwrap();

        assert!(matches!(
            adapter.execute(&effect, &staged, &context).await,
            Err(AdapterError::Toctou(_))
        ));
        assert!(!temp.path().join("notes/prepared.txt").exists());
    }

    #[tokio::test]
    async fn staging_artifact_collision_never_clobbers_either_file() {
        let (temp, adapter) = adapter();
        std::fs::write(temp.path().join("notes/file.txt"), "original").unwrap();
        let context = context();
        let effect = effect("patch", &["notes/file.txt"], Some("approved"));
        let (effect, staged) = preflight_and_stage(&adapter, effect, &context).await;
        let details: FsStage = serde_json::from_value(staged.data.clone()).unwrap();
        let collision = temp.path().join(details.stage_directory).join("displaced");
        std::fs::write(&collision, "unrelated staging file").unwrap();

        assert!(adapter.execute(&effect, &staged, &context).await.is_err());
        assert_eq!(
            std::fs::read_to_string(temp.path().join("notes/file.txt")).unwrap(),
            "original"
        );
        assert_eq!(
            std::fs::read_to_string(collision).unwrap(),
            "unrelated staging file"
        );
    }

    #[tokio::test]
    async fn staged_filesystem_details_are_bound_to_the_transaction_and_preview() {
        let (temp, adapter) = adapter();
        let context = context();
        let effect = effect("create", &["notes/file.txt"], Some("veyra"));
        let (effect, mut staged) = preflight_and_stage(&adapter, effect, &context).await;
        staged.data["stage_directory"] = json!(".veyra/staging/other-transaction/other-effect");

        assert!(matches!(
            adapter.execute(&effect, &staged, &context).await,
            Err(AdapterError::InvalidStage(_))
        ));
        assert!(!temp.path().join("notes/file.txt").exists());
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
            ".VEYRA/journal.db",
            "safe\\..\\outside",
            "notes/file.txt:stream",
            "notes/NUL.txt",
            "notes/trailing.",
        ] {
            assert!(adapter.paths(&effect("read", &[path], None)).is_err());
        }
    }

    #[test]
    fn unsupported_capability_caveats_fail_closed() {
        let (_temp, adapter) = adapter();
        let mut candidate = effect("read", &["notes/file.txt"], None);
        candidate.required_capabilities[0]
            .constraints
            .insert("region".into(), "us-east".into());
        assert!(matches!(
            adapter.validate(&candidate),
            Err(AdapterError::InvalidEffect(_))
        ));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn directory_symlinks_are_rejected_even_when_the_target_is_inside() {
        use std::os::unix::fs::symlink;

        let (temp, adapter) = adapter();
        std::fs::create_dir(temp.path().join("actual")).unwrap();
        std::fs::write(temp.path().join("actual/file"), "inside").unwrap();
        symlink(temp.path().join("actual"), temp.path().join("alias")).unwrap();

        assert!(matches!(
            adapter
                .preflight(&effect("read", &["alias/file"], None), &context())
                .await,
            Err(AdapterError::Containment(_))
        ));
    }
}
