//! Append-only hash-chained event journal and recoverable `SQLite` state.

use std::{
    collections::HashSet,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction as SqlTransaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use veyra_protocol::{
    ApprovalGrant, ApprovalGrantId, ApprovalRequest, AuditEvent, AuditEventId, AuditVerification,
    Capability, CapabilityId, PrincipalId, Receipt, Transaction, TransactionId, TransactionState,
    canonical_digest, canonical_json,
};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DATABASE_SCHEMA_VERSION: &str = "1";
const AUDIT_COUNT_KEY: &str = "audit_event_count";
const AUDIT_HEAD_KEY: &str = "audit_head_hash";
const SNAPSHOT_BINDING_KEY: &str = "transaction_snapshot_binding_version";
const CAPABILITY_BINDING_KEY: &str = "capability_snapshot_binding_version";
const APPROVAL_CONSUMPTION_BINDING_KEY: &str = "approval_consumption_binding_version";
const OBJECT_BINDING_KEY: &str = "immutable_object_binding_version";
const STAGE_BINDING_KEY: &str = "staged_effect_binding_version";
const IDEMPOTENCY_BINDING_KEY: &str = "idempotency_binding_version";
const MAXIMUM_TRANSACTION_PAGE_SIZE: usize = 1_000;
const MAXIMUM_AUDIT_PAGE_SIZE: usize = 10_000;
const MAXIMUM_AUDIT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_AUDIT_JSON_DEPTH: usize = 64;
const MAXIMUM_AUDIT_JSON_NODES: usize = 100_000;
const DATABASE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    transaction_id TEXT,
    event_type TEXT NOT NULL,
    causal_parent TEXT,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS audit_events_transaction_idx
    ON audit_events(transaction_id, sequence);
CREATE INDEX IF NOT EXISTS audit_events_capability_idx
    ON audit_events(json_extract(payload_json, '$.capability_id'), sequence);
CREATE INDEX IF NOT EXISTS audit_events_approval_nonce_idx
    ON audit_events(json_extract(payload_json, '$.approval_nonce'), sequence);
CREATE INDEX IF NOT EXISTS audit_events_object_idx
    ON audit_events(
        json_extract(payload_json, '$.object_kind'),
        json_extract(payload_json, '$.object_id'),
        sequence
    );
CREATE INDEX IF NOT EXISTS audit_events_stage_idx
    ON audit_events(event_type, transaction_id, json_extract(payload_json, '$.effect_id'), sequence);
CREATE INDEX IF NOT EXISTS audit_events_idempotency_idx
    ON audit_events(
        event_type,
        json_extract(payload_json, '$.idempotency_adapter'),
        json_extract(payload_json, '$.idempotency_key'),
        sequence
    );
CREATE TABLE IF NOT EXISTS objects (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(kind, id)
) STRICT;
CREATE INDEX IF NOT EXISTS objects_kind_transaction_idx
    ON objects(kind, json_extract(canonical_json, '$.transaction_id'), created_at, id);
CREATE INDEX IF NOT EXISTS objects_kind_effect_idx
    ON objects(kind, json_extract(canonical_json, '$.effect_id'), created_at, id);
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    state TEXT NOT NULL,
    json TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS transactions_state_updated_idx
    ON transactions(state, updated_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    json TEXT NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
) STRICT;
CREATE INDEX IF NOT EXISTS capabilities_principal_idx
    ON capabilities(json_extract(json, '$.principal_id'), id);
CREATE TABLE IF NOT EXISTS consumed_approval_nonces (
    nonce TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL UNIQUE,
    consumed_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS idempotency (
    adapter TEXT NOT NULL,
    key TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('reserved', 'complete', 'unknown')),
    receipt_json TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(adapter, key)
) STRICT;
CREATE TABLE IF NOT EXISTS staged_effects (
    transaction_id TEXT NOT NULL,
    effect_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    stage_json TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY(transaction_id, effect_id)
) STRICT;
";

type HmacSha256 = Hmac<Sha256>;

/// Durable `SQLite` journal with a process-local connection lock.
#[derive(Clone)]
pub struct Journal {
    connection: Arc<Mutex<Connection>>,
    receipt_key: Arc<[u8; 32]>,
    receipt_key_id: Arc<str>,
}

impl Journal {
    /// Open or initialize a durable journal and receipt-authentication key.
    ///
    /// The key is stored separately from `SQLite` so a database-only attacker cannot forge receipts.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if directories, key material, `SQLite` initialization, or the
    /// existing audit chain cannot be safely read and verified.
    pub fn open(
        database_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, JournalError> {
        let database_path = database_path.as_ref();
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent).map_err(|source| JournalError::Io {
                operation: "create database directory",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let key = load_or_create_key(key_path.as_ref())?;
        let connection = Connection::open(database_path).map_err(JournalError::Database)?;
        Self::from_connection(connection, key, true)
    }

    /// Create an isolated in-memory journal with a caller-provided test key.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if `SQLite` initialization fails.
    pub fn in_memory(key: [u8; 32]) -> Result<Self, JournalError> {
        let connection = Connection::open_in_memory().map_err(JournalError::Database)?;
        Self::from_connection(connection, key, false)
    }

    fn from_connection(
        connection: Connection,
        key: [u8; 32],
        durable: bool,
    ) -> Result<Self, JournalError> {
        initialize(&connection, durable)?;
        let key_digest = Sha256::digest(key);
        let key_id = format!("local-hmac-sha256:{}", encode_hex(&key_digest[..8]));
        let journal = Self {
            connection: Arc::new(Mutex::new(connection)),
            receipt_key: Arc::new(key),
            receipt_key_id: Arc::from(key_id),
        };
        let verification = journal.verify_event_chain()?;
        if !verification.valid {
            return Err(JournalError::Corrupt {
                sequence: verification.first_invalid_sequence,
                reason: verification.message,
            });
        }
        journal.anchor_unbound_transaction_snapshots()?;
        journal.anchor_unbound_capability_snapshots()?;
        journal.anchor_unbound_approval_consumptions()?;
        journal.anchor_unbound_objects()?;
        journal.anchor_unbound_stages()?;
        journal.anchor_unbound_idempotency()?;
        let verification = journal.verify_chain()?;
        if !verification.valid {
            return Err(JournalError::Corrupt {
                sequence: verification.first_invalid_sequence,
                reason: verification.message,
            });
        }
        Ok(journal)
    }

    /// Persist an immutable typed object under a stable kind and identifier.
    ///
    /// Re-inserting the same canonical content is idempotent. Different content under the same
    /// key is rejected instead of silently mutating an approved object.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ObjectConflict`] for different existing content, or a serialization
    /// or database error.
    pub fn put_object<T: Serialize>(
        &self,
        kind: &str,
        id: &str,
        value: &T,
    ) -> Result<String, JournalError> {
        if kind.is_empty()
            || kind.len() > 128
            || kind.chars().any(char::is_control)
            || id.is_empty()
            || id.len() > 512
            || id.chars().any(char::is_control)
        {
            return Err(JournalError::Invariant(
                "immutable object kind or ID is invalid".into(),
            ));
        }
        let bytes = canonical_json(value).map_err(JournalError::Canonical)?;
        let serialized = String::from_utf8(bytes).map_err(|_| {
            JournalError::Invariant("canonical JSON was not valid UTF-8".to_owned())
        })?;
        let digest = canonical_digest(value).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let existing: Option<(String, String)> = sql
            .query_row(
                "SELECT canonical_json, digest FROM objects WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if let Some((existing_json, existing_digest)) = existing {
            verify_object_serialized(&sql, kind, id, &existing_json, &existing_digest)?;
            if existing_digest == digest {
                return Ok(digest);
            }
            return Err(JournalError::ObjectConflict {
                kind: kind.to_owned(),
                id: id.to_owned(),
            });
        }
        if latest_object_digest_optional(&sql, kind, id)?.is_some() {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "immutable {kind} object `{id}` is missing from its snapshot table"
                ),
            });
        }
        sql.execute(
                "INSERT INTO objects(kind, id, canonical_json, digest, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![kind, id, serialized, digest, Utc::now().to_rfc3339()],
            )
            .map_err(JournalError::Database)?;
        append_event_in_transaction(
            &sql,
            None,
            "object.stored",
            Some(id),
            json!({
                "object_kind": kind,
                "object_id": id,
                "object_digest": digest,
            }),
        )?;
        sql.commit().map_err(JournalError::Database)?;
        Ok(digest)
    }

    /// Load and deserialize an immutable object.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::NotFound`] when absent, or a database/serialization error.
    pub fn get_object<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<T, JournalError> {
        let connection = self.lock()?;
        get_object_from_connection(&connection, kind, id)
    }

    /// List all immutable objects of one kind in creation order.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn objects<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
    ) -> Result<Vec<T>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, canonical_json, digest FROM objects WHERE kind = ?1 ORDER BY created_at, id",
            )
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map(params![kind], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(JournalError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::Database)?;
        drop(statement);
        rows.into_iter()
            .map(|(id, serialized, digest)| {
                deserialize_verified_object(&connection, kind, &id, &serialized, &digest)
            })
            .collect()
    }

    /// List immutable objects whose canonical JSON has the exact transaction binding.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or immutable-object integrity error.
    pub fn objects_for_transaction<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        transaction_id: TransactionId,
    ) -> Result<Vec<T>, JournalError> {
        self.objects_by_json_field(kind, "$.transaction_id", &transaction_id.to_string())
    }

    /// List immutable objects whose canonical JSON is bound to one of the supplied effects.
    ///
    /// The effect list is kernel-bounded. Results retain effect order and creation order within
    /// each effect.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or immutable-object integrity error.
    pub fn objects_for_effects<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        effect_ids: &[veyra_protocol::EffectId],
    ) -> Result<Vec<T>, JournalError> {
        let mut values = Vec::new();
        for effect_id in effect_ids {
            values.extend(self.objects_by_json_field(
                kind,
                "$.effect_id",
                &effect_id.to_string(),
            )?);
        }
        Ok(values)
    }

    fn objects_by_json_field<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        field: &'static str,
        value: &str,
    ) -> Result<Vec<T>, JournalError> {
        let connection = self.lock()?;
        objects_by_json_field_from_connection(&connection, kind, field, value)
    }

    /// Insert a new transaction snapshot and its causal audit event atomically.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or journal-integrity error.
    pub fn create_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<AuditEvent, JournalError> {
        let serialized = serde_json::to_string(transaction).map_err(JournalError::Serialization)?;
        let snapshot_digest = canonical_digest(transaction).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        sql.execute(
            "INSERT INTO transactions(id, revision, state, json, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                transaction.id.to_string(),
                i64_from_u64(transaction.revision)?,
                state_name(transaction.state),
                serialized,
                transaction.updated_at.to_rfc3339()
            ],
        )
        .map_err(JournalError::Database)?;
        let event = append_event_in_transaction(
            &sql,
            Some(transaction.id),
            "transaction.created",
            None,
            json!({
                "state": transaction.state,
                "revision": transaction.revision,
                "snapshot_digest": snapshot_digest,
            }),
        )?;
        sql.commit().map_err(JournalError::Database)?;
        Ok(event)
    }

    /// Replace a transaction snapshot and append its transition event atomically.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::RevisionConflict`] unless the stored revision is exactly one less
    /// than the new snapshot revision, or another persistence/integrity error.
    pub fn update_transaction(
        &self,
        transaction: &Transaction,
        event_type: &str,
        causal_parent: Option<&str>,
        payload: Value,
    ) -> Result<AuditEvent, JournalError> {
        let previous_revision = transaction.revision.checked_sub(1).ok_or_else(|| {
            JournalError::Invariant("updated transaction has revision zero".into())
        })?;
        let serialized = serde_json::to_string(transaction).map_err(JournalError::Serialization)?;
        let snapshot_digest = canonical_digest(transaction).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let changed = sql
            .execute(
                "UPDATE transactions SET revision = ?1, state = ?2, json = ?3, updated_at = ?4 WHERE id = ?5 AND revision = ?6",
                params![
                    i64_from_u64(transaction.revision)?,
                    state_name(transaction.state),
                    serialized,
                    transaction.updated_at.to_rfc3339(),
                    transaction.id.to_string(),
                    i64_from_u64(previous_revision)?
                ],
            )
            .map_err(JournalError::Database)?;
        if changed != 1 {
            return Err(JournalError::RevisionConflict {
                transaction_id: transaction.id,
                expected: previous_revision,
            });
        }
        let event = append_event_in_transaction(
            &sql,
            Some(transaction.id),
            event_type,
            causal_parent,
            bind_snapshot_digest(payload, snapshot_digest),
        )?;
        sql.commit().map_err(JournalError::Database)?;
        Ok(event)
    }

    /// Load the latest transaction snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::NotFound`] if absent, or a database/serialization error.
    pub fn transaction(&self, id: TransactionId) -> Result<Transaction, JournalError> {
        let connection = self.lock()?;
        transaction_from_connection(&connection, id)
    }

    /// Run a group of journal reads against one `SQLite` snapshot.
    ///
    /// Writers through any clone of this journal remain blocked until the callback returns. This
    /// prevents aggregate API responses from mixing transaction revisions or causal evidence.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, integrity, or callback error.
    pub fn read_snapshot<T>(
        &self,
        read: impl FnOnce(&JournalRead<'_>) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(JournalError::Database)?;
        let result = {
            let snapshot = JournalRead { connection: &sql };
            read(&snapshot)
        };
        match result {
            Ok(value) => {
                sql.commit().map_err(JournalError::Database)?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    /// List transaction snapshots newest first.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn transactions(&self) -> Result<Vec<Transaction>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, revision, state, json, updated_at FROM transactions ORDER BY updated_at DESC, id DESC",
            )
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(JournalError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::Database)?;
        drop(statement);
        rows.into_iter()
            .map(|(id, revision, state, serialized, updated_at)| {
                let expected_digest = latest_transaction_snapshot_digest(&connection, &id)?;
                deserialize_transaction_snapshot(
                    &id,
                    revision,
                    &state,
                    &serialized,
                    &updated_at,
                    &expected_digest,
                )
            })
            .collect()
    }

    /// List transaction snapshots using a stable, newest-first keyset cursor.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidCursor`] for malformed bounds/cursors, or a database,
    /// serialization, or integrity error.
    pub fn transaction_page(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<JournalPage<Transaction>, JournalError> {
        validate_page_limit(limit, MAXIMUM_TRANSACTION_PAGE_SIZE, "transaction")?;
        let cursor = cursor.map(decode_transaction_cursor).transpose()?;
        let query_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| JournalError::InvalidCursor("transaction page limit is too large"))?;
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(if cursor.is_some() {
                "SELECT id, revision, state, json, updated_at FROM transactions WHERE updated_at < ?1 OR (updated_at = ?1 AND id < ?2) ORDER BY updated_at DESC, id DESC LIMIT ?3"
            } else {
                "SELECT id, revision, state, json, updated_at FROM transactions ORDER BY updated_at DESC, id DESC LIMIT ?1"
            })
            .map_err(JournalError::Database)?;
        let mut rows = if let Some((updated_at, id)) = cursor {
            statement
                .query(params![updated_at, id, query_limit])
                .map_err(JournalError::Database)?
        } else {
            statement
                .query(params![query_limit])
                .map_err(JournalError::Database)?
        };
        let mut raw = Vec::with_capacity(limit.saturating_add(1));
        while let Some(row) = rows.next().map_err(JournalError::Database)? {
            raw.push((
                row.get::<_, String>(0).map_err(JournalError::Database)?,
                row.get::<_, i64>(1).map_err(JournalError::Database)?,
                row.get::<_, String>(2).map_err(JournalError::Database)?,
                row.get::<_, String>(3).map_err(JournalError::Database)?,
                row.get::<_, String>(4).map_err(JournalError::Database)?,
            ));
        }
        drop(rows);
        drop(statement);
        let has_more = raw.len() > limit;
        raw.truncate(limit);
        let next_cursor = has_more
            .then(|| {
                raw.last()
                    .map(|(id, _, _, _, updated_at)| encode_transaction_cursor(updated_at, id))
            })
            .flatten();
        let items = raw
            .into_iter()
            .map(|(id, revision, state, serialized, updated_at)| {
                let expected_digest = latest_transaction_snapshot_digest(&connection, &id)?;
                deserialize_transaction_snapshot(
                    &id,
                    revision,
                    &state,
                    &serialized,
                    &updated_at,
                    &expected_digest,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(JournalPage { items, next_cursor })
    }

    /// Append an audit event without changing a transaction snapshot.
    ///
    /// Payloads are defensively redacted before canonical hashing and storage.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or integrity error.
    pub fn append_event(
        &self,
        transaction_id: Option<TransactionId>,
        event_type: &str,
        causal_parent: Option<&str>,
        payload: Value,
    ) -> Result<AuditEvent, JournalError> {
        reject_reserved_binding_fields(&payload)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let event =
            append_event_in_transaction(&sql, transaction_id, event_type, causal_parent, payload)?;
        sql.commit().map_err(JournalError::Database)?;
        Ok(event)
    }

    /// Verify every event sequence, previous link, and event digest.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error. Chain corruption is represented by a successful
    /// [`AuditVerification`] value whose `valid` field is false.
    pub fn verify_chain(&self) -> Result<AuditVerification, JournalError> {
        let connection = self.lock()?;
        let verification = match verify_events_streaming(&connection) {
            Ok(verification) => verification,
            Err(error) => return integrity_verification_failure(error, 0, "audit events"),
        };
        if !verification.valid {
            return Ok(verification);
        }
        if let Err(error) = verify_transaction_snapshots(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "transaction snapshots",
            );
        }
        if let Err(error) = verify_capability_snapshots(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "capability snapshots",
            );
        }
        if let Err(error) = verify_approval_consumptions(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "approval consumptions",
            );
        }
        if let Err(error) = verify_object_snapshots(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "immutable object snapshots",
            );
        }
        if let Err(error) = verify_staged_effects(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "staged effect snapshots",
            );
        }
        if let Err(error) = verify_idempotency_snapshots(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "idempotency snapshots",
            );
        }
        if let Err(error) = self.verify_idempotency_receipts(&connection) {
            return integrity_verification_failure(
                error,
                verification.events_checked,
                "idempotency receipts",
            );
        }
        Ok(verification)
    }

    /// Export all events as typed JSON-ready values.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn export_events(
        &self,
        transaction_id: Option<TransactionId>,
    ) -> Result<Vec<AuditEvent>, JournalError> {
        let connection = self.lock()?;
        read_events(&connection, transaction_id)
    }

    /// Export one ascending audit-event page after an opaque sequence cursor.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidCursor`] for malformed bounds/cursors, or a database or
    /// serialization error.
    pub fn audit_event_page(
        &self,
        transaction_id: Option<TransactionId>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<JournalPage<AuditEvent>, JournalError> {
        validate_page_limit(limit, MAXIMUM_AUDIT_PAGE_SIZE, "audit")?;
        let after = cursor.map(decode_audit_cursor).transpose()?.unwrap_or(0);
        let after = i64::try_from(after).map_err(|_| {
            JournalError::InvalidCursor("audit cursor exceeds the supported sequence range")
        })?;
        let query_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| JournalError::InvalidCursor("audit page limit is too large"))?;
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(if transaction_id.is_some() {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE transaction_id = ?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3"
            } else {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2"
            })
            .map_err(JournalError::Database)?;
        let mut rows = if let Some(id) = transaction_id {
            statement
                .query(params![id.to_string(), after, query_limit])
                .map_err(JournalError::Database)?
        } else {
            statement
                .query(params![after, query_limit])
                .map_err(JournalError::Database)?
        };
        let mut items = Vec::with_capacity(limit.saturating_add(1));
        while let Some(row) = rows.next().map_err(JournalError::Database)? {
            items.push(audit_event_from_row(row)?);
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = has_more
            .then(|| items.last().map(|event| event.sequence.to_string()))
            .flatten();
        Ok(JournalPage { items, next_cursor })
    }

    /// Export one newest-first audit-event page before an opaque sequence cursor.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidCursor`] for malformed bounds/cursors, or a database or
    /// serialization error.
    pub fn recent_audit_event_page(
        &self,
        transaction_id: Option<TransactionId>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<JournalPage<AuditEvent>, JournalError> {
        validate_page_limit(limit, MAXIMUM_AUDIT_PAGE_SIZE, "audit")?;
        let before = cursor.map(decode_audit_cursor).transpose()?;
        let before = before
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    JournalError::InvalidCursor("audit cursor exceeds the supported sequence range")
                })
            })
            .transpose()?;
        let query_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| JournalError::InvalidCursor("audit page limit is too large"))?;
        let connection = self.lock()?;
        let query = match (transaction_id.is_some(), before.is_some()) {
            (true, true) => {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE transaction_id = ?1 AND sequence < ?2 ORDER BY sequence DESC LIMIT ?3"
            }
            (true, false) => {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE transaction_id = ?1 ORDER BY sequence DESC LIMIT ?2"
            }
            (false, true) => {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE sequence < ?1 ORDER BY sequence DESC LIMIT ?2"
            }
            (false, false) => {
                "SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events ORDER BY sequence DESC LIMIT ?1"
            }
        };
        let mut statement = connection.prepare(query).map_err(JournalError::Database)?;
        let mut rows = match (transaction_id, before) {
            (Some(id), Some(before)) => statement
                .query(params![id.to_string(), before, query_limit])
                .map_err(JournalError::Database)?,
            (Some(id), None) => statement
                .query(params![id.to_string(), query_limit])
                .map_err(JournalError::Database)?,
            (None, Some(before)) => statement
                .query(params![before, query_limit])
                .map_err(JournalError::Database)?,
            (None, None) => statement
                .query(params![query_limit])
                .map_err(JournalError::Database)?,
        };
        let mut items = Vec::with_capacity(limit.saturating_add(1));
        while let Some(row) = rows.next().map_err(JournalError::Database)? {
            items.push(audit_event_from_row(row)?);
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = has_more
            .then(|| items.last().map(|event| event.sequence.to_string()))
            .flatten();
        Ok(JournalPage { items, next_cursor })
    }

    /// Export a concise, human-readable timeline without raw payload interpolation.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn export_text(
        &self,
        transaction_id: Option<TransactionId>,
    ) -> Result<String, JournalError> {
        let events = self.export_events(transaction_id)?;
        let mut output = String::new();
        for event in events {
            writeln!(
                output,
                "{:06} {} {} tx={} hash={}",
                event.sequence,
                event.recorded_at.to_rfc3339(),
                event.event_type,
                event
                    .transaction_id
                    .map_or_else(|| "-".into(), |id| id.to_string()),
                event.hash.get(..12).unwrap_or(&event.hash)
            )
            .map_err(|_| JournalError::Invariant("could not render audit export".into()))?;
        }
        Ok(output)
    }

    /// Persist an issued capability with a zero use count and atomically bind it to the audit
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error, or an object conflict for a reused ID.
    pub fn store_capability(
        &self,
        capability: &Capability,
        issuer_id: PrincipalId,
    ) -> Result<(), JournalError> {
        let serialized =
            String::from_utf8(canonical_json(capability).map_err(JournalError::Canonical)?)
                .map_err(|_| {
                    JournalError::Invariant("canonical capability JSON was not UTF-8".into())
                })?;
        let digest = canonical_digest(capability).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        sql.execute(
            "INSERT INTO capabilities(id, nonce, json, uses, revoked) VALUES (?1, ?2, ?3, 0, 0)",
            params![capability.id.to_string(), capability.nonce, serialized],
        )
        .map_err(JournalError::Database)?;
        append_event_in_transaction(
            &sql,
            capability.transaction_id,
            "capability.issued",
            Some(&issuer_id.to_string()),
            json!({
                "capability_id": capability.id,
                "principal_id": capability.principal_id,
                "intent_id": capability.intent_id,
                "transaction_id": capability.transaction_id,
                "adapter": capability.adapter,
                "operations": capability.operations,
                "resources": capability.resources,
                "expires_at": capability.expires_at,
                "max_uses": capability.max_uses,
                "issuer_id": issuer_id,
                "capability_digest": digest,
                "capability_uses": 0,
                "capability_revoked": false,
            }),
        )?;
        sql.commit().map_err(JournalError::Database)?;
        Ok(())
    }

    /// Return every capability and its persisted use/revocation facts.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn capabilities(&self) -> Result<Vec<(Capability, CapabilityFacts)>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT id, nonce, json, uses, revoked FROM capabilities ORDER BY id")
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            })
            .map_err(JournalError::Database)?;
        rows.map(|row| {
            let (id, nonce, serialized, uses, revoked) = row.map_err(JournalError::Database)?;
            verify_capability_row(&connection, &id, &nonce, &serialized, uses, revoked)
        })
        .collect()
    }

    /// Return audit-verified capabilities for exactly one principal.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or capability-integrity error.
    pub fn capabilities_for_principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Vec<(Capability, CapabilityFacts)>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, nonce, json, uses, revoked FROM capabilities WHERE json_extract(json, '$.principal_id') = ?1 ORDER BY id",
            )
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map(params![principal_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            })
            .map_err(JournalError::Database)?;
        rows.map(|row| {
            let (id, nonce, serialized, uses, revoked) = row.map_err(JournalError::Database)?;
            verify_capability_row(&connection, &id, &nonce, &serialized, uses, revoked)
        })
        .collect()
    }

    /// Atomically consume one use from every capability ID.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::CapabilityUnavailable`] and rolls back all increments if any grant
    /// is missing, revoked, or exhausted.
    pub fn consume_capabilities(&self, ids: &[CapabilityId]) -> Result<(), JournalError> {
        self.consume_authority(ids, None)
    }

    /// Atomically consume capability uses and an optional human-approval nonce.
    ///
    /// This is the effect authority commit point: either every capability use, the nonce replay
    /// guard, and their audit evidence persist, or none do.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::CapabilityUnavailable`] or [`JournalError::ApprovalReplay`] without
    /// committing a partial authority update.
    pub fn consume_authority(
        &self,
        ids: &[CapabilityId],
        approval: Option<&ApprovalGrant>,
    ) -> Result<(), JournalError> {
        let unique: HashSet<_> = ids.iter().copied().collect();
        if unique.len() != ids.len() {
            return Err(JournalError::Invariant(
                "duplicate capability IDs in one authorization".into(),
            ));
        }
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        for id in ids {
            let row: Option<(String, String, String, i64, bool)> = sql
                .query_row(
                    "SELECT id, nonce, json, uses, revoked FROM capabilities WHERE id = ?1",
                    params![id.to_string()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(JournalError::Database)?;
            let Some((stored_id, nonce, serialized, uses, revoked)) = row else {
                return Err(JournalError::CapabilityUnavailable(*id));
            };
            let (capability, facts) =
                verify_capability_row(&sql, &stored_id, &nonce, &serialized, uses, revoked)?;
            if facts.revoked || facts.uses >= capability.max_uses {
                return Err(JournalError::CapabilityUnavailable(*id));
            }
            let next_uses = facts
                .uses
                .checked_add(1)
                .ok_or_else(|| JournalError::Invariant("capability use count overflow".into()))?;
            sql.execute(
                "UPDATE capabilities SET uses = uses + 1 WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(JournalError::Database)?;
            append_event_in_transaction(
                &sql,
                capability.transaction_id,
                "capability.consumed",
                Some(&capability.id.to_string()),
                json!({
                    "capability_id": capability.id,
                    "capability_uses": next_uses,
                    "capability_revoked": false,
                    "max_uses": capability.max_uses,
                }),
            )?;
        }
        if let Some(grant) = approval {
            let consumed_at = Utc::now().to_rfc3339();
            match sql.execute(
                "INSERT INTO consumed_approval_nonces(nonce, grant_id, consumed_at) VALUES (?1, ?2, ?3)",
                params![grant.nonce, grant.id.to_string(), consumed_at],
            ) {
                Ok(1) => {}
                Ok(_) => {
                    return Err(JournalError::Invariant(
                        "approval consumption changed an unexpected number of rows".into(),
                    ));
                }
                Err(error) if is_constraint_violation(&error) => {
                    return Err(JournalError::ApprovalReplay);
                }
                Err(error) => return Err(JournalError::Database(error)),
            }
            append_event_in_transaction(
                &sql,
                Some(grant.transaction_id),
                "approval.consumed",
                Some(&grant.id.to_string()),
                json!({
                    "approval_nonce": grant.nonce,
                    "grant_id": grant.id,
                    "consumed_at": consumed_at,
                }),
            )?;
        }
        sql.commit().map_err(JournalError::Database)?;
        Ok(())
    }

    /// Revoke a capability so future policy checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::CapabilityUnavailable`] if the ID is unknown, or a database error.
    pub fn revoke_capability(
        &self,
        id: CapabilityId,
        revoker_id: PrincipalId,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let row: Option<(String, String, String, i64, bool)> = sql
            .query_row(
                "SELECT id, nonce, json, uses, revoked FROM capabilities WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((stored_id, nonce, serialized, uses, revoked)) = row else {
            return Err(JournalError::CapabilityUnavailable(id));
        };
        let (capability, facts) =
            verify_capability_row(&sql, &stored_id, &nonce, &serialized, uses, revoked)?;
        if facts.revoked {
            return Err(JournalError::CapabilityUnavailable(id));
        }
        let changed = sql
            .execute(
                "UPDATE capabilities SET revoked = 1 WHERE id = ?1 AND revoked = 0",
                params![id.to_string()],
            )
            .map_err(JournalError::Database)?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "capability revocation changed an unexpected number of rows".into(),
            ));
        }
        append_event_in_transaction(
            &sql,
            capability.transaction_id,
            "capability.revoked",
            Some(&revoker_id.to_string()),
            json!({
                "capability_id": capability.id,
                "revoker_id": revoker_id,
                "capability_uses": facts.uses,
                "capability_revoked": true,
                "max_uses": capability.max_uses,
            }),
        )?;
        sql.commit().map_err(JournalError::Database)
    }

    /// Persist an approval request.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or immutable-object conflict error.
    pub fn store_approval_request(&self, request: &ApprovalRequest) -> Result<(), JournalError> {
        self.put_object("approval_request", &request.id.to_string(), request)?;
        Ok(())
    }

    /// Persist an approval grant.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or immutable-object conflict error.
    pub fn store_approval_grant(&self, grant: &ApprovalGrant) -> Result<(), JournalError> {
        self.put_object("approval_grant", &grant.id.to_string(), grant)?;
        Ok(())
    }

    /// Atomically mark an approval nonce consumed, protecting against replay.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ApprovalReplay`] when already consumed, or a database error.
    pub fn consume_approval(&self, grant: &ApprovalGrant) -> Result<(), JournalError> {
        self.consume_authority(&[], Some(grant))
    }

    /// Return all approval nonces that have already authorized execution.
    ///
    /// # Errors
    ///
    /// Returns a database error.
    pub fn consumed_approval_nonces(&self) -> Result<HashSet<String>, JournalError> {
        let connection = self.lock()?;
        verify_approval_consumptions(&connection)?;
        let mut statement = connection
            .prepare("SELECT nonce FROM consumed_approval_nonces")
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| row.get(0))
            .map_err(JournalError::Database)?;
        rows.map(|row| row.map_err(JournalError::Database))
            .collect()
    }

    /// Check one approval nonce without materializing the complete replay history.
    ///
    /// # Errors
    ///
    /// Returns a database error.
    pub fn approval_nonce_consumed(&self, nonce: &str) -> Result<bool, JournalError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT grant_id, consumed_at FROM consumed_approval_nonces WHERE nonce = ?1",
                params![nonce],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let binding = latest_approval_consumption(&connection, nonce)?;
        match (row, binding) {
            (None, None) => Ok(false),
            (Some((grant_id, consumed_at)), Some(binding))
                if binding.grant_id == grant_id && binding.consumed_at == consumed_at =>
            {
                Ok(true)
            }
            _ => Err(JournalError::Corrupt {
                sequence: None,
                reason: "approval nonce replay state disagrees with its audit binding".into(),
            }),
        }
    }

    /// Reserve an adapter/idempotency key before crossing the side-effect boundary.
    ///
    /// # Errors
    ///
    /// Returns a database or receipt deserialization error.
    pub fn reserve_execution(
        &self,
        adapter: &str,
        key: &str,
        effect_digest: &str,
    ) -> Result<IdempotencyReservation, JournalError> {
        validate_idempotency_arguments(adapter, key, effect_digest)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let existing: Option<(String, String, Option<String>, String)> = sql
            .query_row(
                "SELECT effect_digest, status, receipt_json, updated_at FROM idempotency WHERE adapter = ?1 AND key = ?2",
                params![adapter, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let result = match existing {
            None => {
                if latest_idempotency_binding_optional(&sql, adapter, key)?.is_some() {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: "idempotency reservation is missing from its snapshot table".into(),
                    });
                }
                let updated_at = Utc::now().to_rfc3339();
                sql.execute(
                    "INSERT INTO idempotency(adapter, key, effect_digest, status, receipt_json, updated_at) VALUES (?1, ?2, ?3, 'reserved', NULL, ?4)",
                    params![adapter, key, effect_digest, updated_at],
                )
                .map_err(JournalError::Database)?;
                append_event_in_transaction(
                    &sql,
                    None,
                    "idempotency.reserved",
                    None,
                    idempotency_payload(adapter, key, effect_digest, "reserved", None, &updated_at),
                )?;
                IdempotencyReservation::Acquired
            }
            Some((stored_digest, status, receipt_json, updated_at)) => {
                verify_idempotency_row(
                    &sql,
                    adapter,
                    key,
                    &stored_digest,
                    &status,
                    receipt_json.as_deref(),
                    &updated_at,
                )?;
                if stored_digest != effect_digest {
                    IdempotencyReservation::Conflict
                } else if status == "complete" {
                    let serialized = receipt_json.ok_or_else(|| JournalError::Corrupt {
                        sequence: None,
                        reason: "completed idempotency reservation has no receipt".into(),
                    })?;
                    let receipt: Receipt =
                        serde_json::from_str(&serialized).map_err(JournalError::Serialization)?;
                    self.verify_receipt(&receipt)?;
                    IdempotencyReservation::Completed(Box::new(receipt))
                } else if status == "unknown" {
                    IdempotencyReservation::Unknown
                } else {
                    IdempotencyReservation::InProgress
                }
            }
        };
        sql.commit().map_err(JournalError::Database)?;
        Ok(result)
    }

    /// Complete an idempotency reservation with an authenticated receipt.
    ///
    /// # Errors
    ///
    /// Returns an invariant error unless exactly one matching reservation exists, or a database or
    /// serialization error.
    pub fn complete_execution(
        &self,
        adapter: &str,
        key: &str,
        effect_digest: &str,
        receipt: &Receipt,
    ) -> Result<(), JournalError> {
        validate_idempotency_arguments(adapter, key, effect_digest)?;
        self.verify_receipt(receipt)?;
        if receipt.effect_digest != effect_digest {
            return Err(JournalError::Invariant(
                "receipt is not bound to the reserved effect digest".into(),
            ));
        }
        let serialized = serde_json::to_string(receipt).map_err(JournalError::Serialization)?;
        let receipt_digest = canonical_digest(receipt).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let existing: Option<(String, String, Option<String>, String)> = sql
            .query_row(
                "SELECT effect_digest, status, receipt_json, updated_at FROM idempotency WHERE adapter = ?1 AND key = ?2",
                params![adapter, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((stored_digest, status, stored_receipt, stored_updated_at)) = existing else {
            return Err(JournalError::Invariant(
                "idempotency reservation was not exclusively held".into(),
            ));
        };
        verify_idempotency_row(
            &sql,
            adapter,
            key,
            &stored_digest,
            &status,
            stored_receipt.as_deref(),
            &stored_updated_at,
        )?;
        if stored_digest != effect_digest || status != "reserved" {
            return Err(JournalError::Invariant(
                "idempotency reservation was not exclusively held".into(),
            ));
        }
        let updated_at = Utc::now().to_rfc3339();
        let changed = sql
            .execute(
                "UPDATE idempotency SET status = 'complete', receipt_json = ?1, updated_at = ?2 WHERE adapter = ?3 AND key = ?4 AND effect_digest = ?5 AND status = 'reserved'",
                params![serialized, updated_at, adapter, key, effect_digest],
            )
            .map_err(JournalError::Database)?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "idempotency reservation was not exclusively held".into(),
            ));
        }
        append_event_in_transaction(
            &sql,
            Some(receipt.transaction_id),
            "idempotency.completed",
            Some(&receipt.id.to_string()),
            idempotency_payload(
                adapter,
                key,
                effect_digest,
                "complete",
                Some(&receipt_digest),
                &updated_at,
            ),
        )?;
        sql.commit().map_err(JournalError::Database)
    }

    /// Mark an in-flight reservation ambiguous after a crash or malformed adapter response.
    ///
    /// # Errors
    ///
    /// Returns a database or invariant error.
    pub fn mark_execution_unknown(
        &self,
        adapter: &str,
        key: &str,
        effect_digest: &str,
    ) -> Result<(), JournalError> {
        validate_idempotency_arguments(adapter, key, effect_digest)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let existing: Option<(String, String, Option<String>, String)> = sql
            .query_row(
                "SELECT effect_digest, status, receipt_json, updated_at FROM idempotency WHERE adapter = ?1 AND key = ?2",
                params![adapter, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((stored_digest, status, receipt_json, stored_updated_at)) = existing else {
            return Err(JournalError::Invariant(
                "could not mark idempotency reservation unknown".into(),
            ));
        };
        verify_idempotency_row(
            &sql,
            adapter,
            key,
            &stored_digest,
            &status,
            receipt_json.as_deref(),
            &stored_updated_at,
        )?;
        if stored_digest != effect_digest || status != "reserved" {
            return Err(JournalError::Invariant(
                "could not mark idempotency reservation unknown".into(),
            ));
        }
        let updated_at = Utc::now().to_rfc3339();
        let changed = sql
            .execute(
                "UPDATE idempotency SET status = 'unknown', updated_at = ?1 WHERE adapter = ?2 AND key = ?3 AND effect_digest = ?4 AND status = 'reserved'",
                params![updated_at, adapter, key, effect_digest],
            )
            .map_err(JournalError::Database)?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "could not mark idempotency reservation unknown".into(),
            ));
        }
        append_event_in_transaction(
            &sql,
            None,
            "idempotency.unknown",
            None,
            idempotency_payload(adapter, key, effect_digest, "unknown", None, &updated_at),
        )?;
        sql.commit().map_err(JournalError::Database)
    }

    /// Store adapter staging data needed for rollback and crash recovery.
    ///
    /// # Errors
    ///
    /// Returns a serialization, database, or immutable-stage conflict error.
    pub fn store_stage<T: Serialize>(
        &self,
        transaction_id: TransactionId,
        effect_id: veyra_protocol::EffectId,
        adapter: &str,
        stage: &T,
    ) -> Result<(), JournalError> {
        let serialized = String::from_utf8(canonical_json(stage).map_err(JournalError::Canonical)?)
            .map_err(|_| JournalError::Invariant("canonical stage was not UTF-8".into()))?;
        let stage_digest = canonical_digest(stage).map_err(JournalError::Canonical)?;
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        match sql.execute(
            "INSERT INTO staged_effects(transaction_id, effect_id, adapter, stage_json, status) VALUES (?1, ?2, ?3, ?4, 'staged')",
            params![transaction_id.to_string(), effect_id.to_string(), adapter, serialized],
        ) {
            Ok(1) => {}
            Ok(_) => return Err(JournalError::Invariant("stage insert changed no row".into())),
            Err(error) if is_constraint_violation(&error) => {
                return Err(JournalError::Invariant("effect was already staged".into()));
            }
            Err(error) => return Err(JournalError::Database(error)),
        }
        append_event_in_transaction(
            &sql,
            Some(transaction_id),
            "stage.stored",
            Some(&effect_id.to_string()),
            json!({
                "effect_id": effect_id,
                "adapter": adapter,
                "stage_digest": stage_digest,
                "stage_status": "staged",
            }),
        )?;
        sql.commit().map_err(JournalError::Database)
    }

    /// Load persisted adapter staging data.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::NotFound`] if absent, or a database/serialization error.
    pub fn stage<T: DeserializeOwned>(
        &self,
        transaction_id: TransactionId,
        effect_id: veyra_protocol::EffectId,
    ) -> Result<T, JournalError> {
        let connection = self.lock()?;
        let row: Option<(String, String, String)> = connection
            .query_row(
                "SELECT adapter, stage_json, status FROM staged_effects WHERE transaction_id = ?1 AND effect_id = ?2",
                params![transaction_id.to_string(), effect_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((adapter, serialized, status)) = row else {
            if latest_stage_binding_optional(&connection, transaction_id, effect_id)?.is_some() {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "stage for effect `{effect_id}` is missing from its snapshot table"
                    ),
                });
            }
            return Err(JournalError::NotFound {
                kind: "stage".into(),
                id: effect_id.to_string(),
            });
        };
        verify_stage_serialized(
            &connection,
            transaction_id,
            effect_id,
            &adapter,
            &serialized,
            &status,
        )?;
        serde_json::from_str(&serialized).map_err(JournalError::Serialization)
    }

    /// Authenticate a kernel-issued receipt, overwriting any untrusted authentication fields.
    ///
    /// # Errors
    ///
    /// Returns a canonical serialization error.
    pub fn sign_receipt(&self, mut receipt: Receipt) -> Result<Receipt, JournalError> {
        receipt.signer_key_id = self.receipt_key_id.to_string();
        receipt.authentication.clear();
        if !receipt_body_has_safe_shape(&receipt) {
            return Err(JournalError::Invariant(
                "receipt body is malformed or exceeds journal bounds".into(),
            ));
        }
        let bytes = canonical_json(&receipt).map_err(JournalError::Canonical)?;
        let mut mac = HmacSha256::new_from_slice(self.receipt_key.as_ref())
            .map_err(|_| JournalError::Invariant("invalid receipt key length".into()))?;
        mac.update(&bytes);
        receipt.authentication = encode_hex(&mac.finalize().into_bytes());
        Ok(receipt)
    }

    /// Verify the key identifier and authentication tag of a receipt.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ForgedReceipt`] for a mismatch, or a serialization error.
    pub fn verify_receipt(&self, receipt: &Receipt) -> Result<(), JournalError> {
        if receipt.signer_key_id != self.receipt_key_id.as_ref()
            || !valid_sha256_hex(&receipt.authentication)
            || !receipt_body_has_safe_shape(receipt)
        {
            return Err(JournalError::ForgedReceipt);
        }
        let provided = decode_hex(&receipt.authentication).ok_or(JournalError::ForgedReceipt)?;
        let mut unsigned = receipt.clone();
        unsigned.authentication.clear();
        let bytes = canonical_json(&unsigned).map_err(JournalError::Canonical)?;
        let mut mac = HmacSha256::new_from_slice(self.receipt_key.as_ref())
            .map_err(|_| JournalError::Invariant("invalid receipt key length".into()))?;
        mac.update(&bytes);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice().ct_eq(&provided).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(JournalError::ForgedReceipt)
        }
    }

    /// Classify nonterminal transactions after a daemon restart.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn recovery_actions(&self) -> Result<Vec<RecoveryRecord>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, revision, state, json, updated_at FROM transactions WHERE state IN ('draft', 'planned', 'preflighted', 'awaiting_approval', 'approved', 'staged', 'executing', 'verifying', 'compensating', 'manual_recovery') ORDER BY updated_at, id",
            )
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(JournalError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::Database)?;
        drop(statement);
        rows.into_iter()
            .map(|(id, revision, state, serialized, updated_at)| {
                let expected_digest = latest_transaction_snapshot_digest(&connection, &id)?;
                let transaction = deserialize_transaction_snapshot(
                    &id,
                    revision,
                    &state,
                    &serialized,
                    &updated_at,
                    &expected_digest,
                )?;
                recovery_record(&transaction)
            })
            .collect()
    }

    /// List active recovery records in a stable newest-first keyset page.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidCursor`] for malformed bounds/cursors, or a database,
    /// serialization, or integrity error.
    pub fn recovery_action_page(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<JournalPage<RecoveryRecord>, JournalError> {
        validate_page_limit(limit, MAXIMUM_TRANSACTION_PAGE_SIZE, "transaction")?;
        let cursor = cursor.map(decode_transaction_cursor).transpose()?;
        let query_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| JournalError::InvalidCursor("recovery page limit is too large"))?;
        let connection = self.lock()?;
        let active = "('draft', 'planned', 'preflighted', 'awaiting_approval', 'approved', 'staged', 'executing', 'verifying', 'compensating', 'manual_recovery')";
        let query = if cursor.is_some() {
            format!(
                "SELECT id, revision, state, json, updated_at FROM transactions WHERE state IN {active} AND (updated_at < ?1 OR (updated_at = ?1 AND id < ?2)) ORDER BY updated_at DESC, id DESC LIMIT ?3"
            )
        } else {
            format!(
                "SELECT id, revision, state, json, updated_at FROM transactions WHERE state IN {active} ORDER BY updated_at DESC, id DESC LIMIT ?1"
            )
        };
        let mut statement = connection.prepare(&query).map_err(JournalError::Database)?;
        let mut rows = if let Some((updated_at, id)) = cursor {
            statement
                .query(params![updated_at, id, query_limit])
                .map_err(JournalError::Database)?
        } else {
            statement
                .query(params![query_limit])
                .map_err(JournalError::Database)?
        };
        let mut raw = Vec::with_capacity(limit.saturating_add(1));
        while let Some(row) = rows.next().map_err(JournalError::Database)? {
            raw.push((
                row.get::<_, String>(0).map_err(JournalError::Database)?,
                row.get::<_, i64>(1).map_err(JournalError::Database)?,
                row.get::<_, String>(2).map_err(JournalError::Database)?,
                row.get::<_, String>(3).map_err(JournalError::Database)?,
                row.get::<_, String>(4).map_err(JournalError::Database)?,
            ));
        }
        drop(rows);
        drop(statement);
        let has_more = raw.len() > limit;
        raw.truncate(limit);
        let next_cursor = has_more
            .then(|| {
                raw.last()
                    .map(|(id, _, _, _, updated_at)| encode_transaction_cursor(updated_at, id))
            })
            .flatten();
        let items = raw
            .into_iter()
            .map(|(id, revision, state, serialized, updated_at)| {
                let expected_digest = latest_transaction_snapshot_digest(&connection, &id)?;
                let transaction = deserialize_transaction_snapshot(
                    &id,
                    revision,
                    &state,
                    &serialized,
                    &updated_at,
                    &expected_digest,
                )?;
                recovery_record(&transaction)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(JournalPage { items, next_cursor })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, JournalError> {
        self.connection.lock().map_err(|_| JournalError::Poisoned)
    }

    fn verify_event_chain(&self) -> Result<AuditVerification, JournalError> {
        let connection = self.lock()?;
        verify_events_streaming(&connection)
    }

    fn verify_idempotency_receipts(&self, connection: &Connection) -> Result<(), JournalError> {
        let mut statement = connection
            .prepare(
                "SELECT receipt_json FROM idempotency WHERE status = 'complete' ORDER BY adapter, key",
            )
            .map_err(JournalError::Database)?;
        let mut rows = statement.query([]).map_err(JournalError::Database)?;
        while let Some(row) = rows.next().map_err(JournalError::Database)? {
            let serialized: Option<String> = row.get(0).map_err(JournalError::Database)?;
            let serialized = serialized.ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "completed idempotency reservation has no receipt".into(),
            })?;
            let receipt: Receipt =
                serde_json::from_str(&serialized).map_err(|_| JournalError::Corrupt {
                    sequence: None,
                    reason: "completed idempotency reservation has a malformed receipt".into(),
                })?;
            self.verify_receipt(&receipt)?;
        }
        Ok(())
    }

    fn anchor_unbound_transaction_snapshots(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![SNAPSHOT_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported transaction snapshot binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let transaction_ids = {
            let mut statement = sql
                .prepare("SELECT id FROM transactions ORDER BY id")
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for id in transaction_ids {
            let (revision, state, serialized, updated_at): (i64, String, String, String) = sql
                .query_row(
                    "SELECT revision, state, json, updated_at FROM transactions WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(JournalError::Database)?;
            let transaction = deserialize_transaction_snapshot_index(
                &id,
                revision,
                &state,
                &serialized,
                &updated_at,
            )?;
            let actual_digest = canonical_digest(&transaction).map_err(JournalError::Canonical)?;
            match latest_transaction_snapshot_digest_optional(&sql, &id)? {
                Some(expected_digest) if expected_digest != actual_digest => {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: format!(
                            "transaction snapshot `{id}` disagrees with its audit-bound digest"
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    append_event_in_transaction(
                        &sql,
                        Some(transaction.id),
                        "transaction.snapshot_anchored",
                        None,
                        json!({
                            "state": transaction.state,
                            "revision": transaction.revision,
                            "snapshot_digest": actual_digest,
                            "migration_anchor": true,
                        }),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![SNAPSHOT_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }

    fn anchor_unbound_capability_snapshots(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![CAPABILITY_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported capability snapshot binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let capability_ids = {
            let mut statement = sql
                .prepare("SELECT id FROM capabilities ORDER BY id")
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for id in capability_ids {
            let (nonce, serialized, uses, revoked): (String, String, i64, bool) = sql
                .query_row(
                    "SELECT nonce, json, uses, revoked FROM capabilities WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(JournalError::Database)?;
            let capability = deserialize_capability_index(&id, &nonce, &serialized)?;
            let facts = capability_facts(uses, revoked, &id)?;
            let actual_digest = canonical_digest(&capability).map_err(JournalError::Canonical)?;
            match latest_capability_binding(&sql, &id)? {
                Some(binding)
                    if binding.digest != actual_digest
                        || binding.uses != facts.uses
                        || binding.revoked != facts.revoked =>
                {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: format!(
                            "capability snapshot `{id}` disagrees with its audit-bound state"
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    append_event_in_transaction(
                        &sql,
                        capability.transaction_id,
                        "capability.snapshot_anchored",
                        None,
                        json!({
                            "capability_id": capability.id,
                            "capability_digest": actual_digest,
                            "capability_uses": facts.uses,
                            "capability_revoked": facts.revoked,
                            "migration_anchor": true,
                        }),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![CAPABILITY_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }

    fn anchor_unbound_approval_consumptions(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![APPROVAL_CONSUMPTION_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported approval consumption binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let consumptions = {
            let mut statement = sql
                .prepare(
                    "SELECT nonce, grant_id, consumed_at FROM consumed_approval_nonces ORDER BY nonce",
                )
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for (nonce, grant_id, consumed_at) in consumptions {
            validate_approval_consumption(&nonce, &grant_id, &consumed_at)?;
            match latest_approval_consumption(&sql, &nonce)? {
                Some(binding)
                    if binding.grant_id != grant_id || binding.consumed_at != consumed_at =>
                {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: "approval nonce replay state disagrees with its audit binding"
                            .into(),
                    });
                }
                Some(_) => {}
                None => {
                    append_event_in_transaction(
                        &sql,
                        None,
                        "approval.consumption_anchored",
                        Some(&grant_id),
                        json!({
                            "approval_nonce": nonce,
                            "grant_id": grant_id,
                            "consumed_at": consumed_at,
                            "migration_anchor": true,
                        }),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![APPROVAL_CONSUMPTION_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }

    fn anchor_unbound_objects(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![OBJECT_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported immutable object binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let object_keys = {
            let mut statement = sql
                .prepare("SELECT kind, id FROM objects ORDER BY kind, id")
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for (kind, id) in object_keys {
            let (serialized, stored_digest): (String, String) = sql
                .query_row(
                    "SELECT canonical_json, digest FROM objects WHERE kind = ?1 AND id = ?2",
                    params![kind, id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(JournalError::Database)?;
            let actual_digest = object_actual_digest(&kind, &id, &serialized)?;
            if actual_digest != stored_digest {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: format!("immutable {kind} object `{id}` has a digest mismatch"),
                });
            }
            match latest_object_digest_optional(&sql, &kind, &id)? {
                Some(expected_digest) if expected_digest != actual_digest => {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: format!(
                            "immutable {kind} object `{id}` disagrees with its audit-bound digest"
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    append_event_in_transaction(
                        &sql,
                        None,
                        "object.snapshot_anchored",
                        Some(&id),
                        json!({
                            "object_kind": kind,
                            "object_id": id,
                            "object_digest": actual_digest,
                            "migration_anchor": true,
                        }),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![OBJECT_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }

    fn anchor_unbound_stages(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![STAGE_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported staged-effect binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let stage_keys = {
            let mut statement = sql
                .prepare(
                    "SELECT transaction_id, effect_id FROM staged_effects ORDER BY transaction_id, effect_id",
                )
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for (transaction_id, effect_id) in stage_keys {
            let transaction_id =
                transaction_id
                    .parse::<TransactionId>()
                    .map_err(|_| JournalError::Corrupt {
                        sequence: None,
                        reason: "staged effect has an invalid transaction ID".into(),
                    })?;
            let effect_id = effect_id.parse::<veyra_protocol::EffectId>().map_err(|_| {
                JournalError::Corrupt {
                    sequence: None,
                    reason: "staged effect has an invalid effect ID".into(),
                }
            })?;
            let (adapter, serialized, status): (String, String, String) = sql
                .query_row(
                    "SELECT adapter, stage_json, status FROM staged_effects WHERE transaction_id = ?1 AND effect_id = ?2",
                    params![transaction_id.to_string(), effect_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(JournalError::Database)?;
            let actual_digest = stage_actual_digest(&serialized)?;
            match latest_stage_binding_optional(&sql, transaction_id, effect_id)? {
                Some(binding)
                    if binding.adapter != adapter
                        || binding.digest != actual_digest
                        || binding.status != status =>
                {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: format!(
                            "stage for effect `{effect_id}` disagrees with its audit-bound state"
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    validate_stage_index(&adapter, &status)?;
                    append_event_in_transaction(
                        &sql,
                        Some(transaction_id),
                        "stage.snapshot_anchored",
                        Some(&effect_id.to_string()),
                        json!({
                            "effect_id": effect_id,
                            "adapter": adapter,
                            "stage_digest": actual_digest,
                            "stage_status": status,
                            "migration_anchor": true,
                        }),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![STAGE_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }

    fn anchor_unbound_idempotency(&self) -> Result<(), JournalError> {
        let mut connection = self.lock()?;
        let binding_version: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![IDEMPOTENCY_BINDING_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if binding_version.as_deref() == Some("1") {
            return Ok(());
        }
        if binding_version.is_some() {
            return Err(JournalError::Invariant(
                "unsupported idempotency binding version".into(),
            ));
        }
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let keys = {
            let mut statement = sql
                .prepare("SELECT adapter, key FROM idempotency ORDER BY adapter, key")
                .map_err(JournalError::Database)?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(JournalError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(JournalError::Database)?
        };
        for (adapter, key) in keys {
            let (effect_digest, status, receipt_json, updated_at): (
                String,
                String,
                Option<String>,
                String,
            ) = sql
                .query_row(
                    "SELECT effect_digest, status, receipt_json, updated_at FROM idempotency WHERE adapter = ?1 AND key = ?2",
                    params![adapter, key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(JournalError::Database)?;
            validate_idempotency_row(
                &adapter,
                &key,
                &effect_digest,
                &status,
                receipt_json.as_deref(),
                &updated_at,
            )?;
            let receipt_digest = idempotency_receipt_digest(receipt_json.as_deref())?;
            match latest_idempotency_binding_optional(&sql, &adapter, &key)? {
                Some(binding)
                    if binding.effect_digest != effect_digest
                        || binding.status != status
                        || binding.receipt_digest != receipt_digest
                        || binding.updated_at != updated_at =>
                {
                    return Err(JournalError::Corrupt {
                        sequence: None,
                        reason: "idempotency snapshot disagrees with its audit-bound state".into(),
                    });
                }
                Some(_) => {}
                None => {
                    append_event_in_transaction(
                        &sql,
                        None,
                        "idempotency.snapshot_anchored",
                        None,
                        idempotency_payload(
                            &adapter,
                            &key,
                            &effect_digest,
                            &status,
                            receipt_digest.as_deref(),
                            &updated_at,
                        ),
                    )?;
                }
            }
        }
        sql.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, '1')",
            params![IDEMPOTENCY_BINDING_KEY],
        )
        .map_err(JournalError::Database)?;
        sql.commit().map_err(JournalError::Database)
    }
}

/// Persisted facts consumed by the policy engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityFacts {
    /// Number of successful prior authorizations.
    pub uses: u32,
    /// Whether the capability is revoked.
    pub revoked: bool,
}

/// Read-only view pinned to one `SQLite` snapshot.
pub struct JournalRead<'a> {
    connection: &'a Connection,
}

impl JournalRead<'_> {
    /// Load the latest transaction revision visible in this snapshot.
    ///
    /// # Errors
    ///
    /// Returns a not-found, database, serialization, or integrity error.
    pub fn transaction(&self, id: TransactionId) -> Result<Transaction, JournalError> {
        transaction_from_connection(self.connection, id)
    }

    /// Load and integrity-check one immutable object in this snapshot.
    ///
    /// # Errors
    ///
    /// Returns a not-found, database, serialization, or integrity error.
    pub fn get_object<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<T, JournalError> {
        get_object_from_connection(self.connection, kind, id)
    }

    /// Load immutable objects with an exact transaction binding in creation order.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or integrity error.
    pub fn objects_for_transaction<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        transaction_id: TransactionId,
    ) -> Result<Vec<T>, JournalError> {
        objects_by_json_field_from_connection(
            self.connection,
            kind,
            "$.transaction_id",
            &transaction_id.to_string(),
        )
    }

    /// Load immutable objects for the supplied effects, retaining effect order.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or integrity error.
    pub fn objects_for_effects<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        effect_ids: &[veyra_protocol::EffectId],
    ) -> Result<Vec<T>, JournalError> {
        let mut values = Vec::new();
        for effect_id in effect_ids {
            values.extend(objects_by_json_field_from_connection(
                self.connection,
                kind,
                "$.effect_id",
                &effect_id.to_string(),
            )?);
        }
        Ok(values)
    }

    /// Export the causal audit events visible in this snapshot.
    ///
    /// # Errors
    ///
    /// Returns a database, serialization, or integrity error.
    pub fn export_events(
        &self,
        transaction_id: Option<TransactionId>,
    ) -> Result<Vec<AuditEvent>, JournalError> {
        read_events(self.connection, transaction_id)
    }
}

/// One bounded keyset page from the durable journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalPage<T> {
    /// Values in stable journal order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, absent when the scan is complete.
    pub next_cursor: Option<String>,
}

/// Result of reserving an idempotency key.
#[derive(Clone, Debug, PartialEq)]
pub enum IdempotencyReservation {
    /// This caller atomically acquired the previously unseen key.
    Acquired,
    /// The same effect already holds an in-flight reservation.
    InProgress,
    /// The same effect completed earlier; return the stored receipt.
    Completed(Box<Receipt>),
    /// The key belongs to different effect content.
    Conflict,
    /// A crash left the external outcome ambiguous.
    Unknown,
}

/// Recommended restart behavior for a persisted transaction.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// No external effect may be in flight; forward processing may resume.
    ResumeSafe,
    /// Automatic execution could duplicate or worsen an ambiguous effect.
    ManualRecovery,
}

/// One transaction discovered during restart recovery.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecoveryRecord {
    /// Persisted transaction ID.
    pub transaction_id: TransactionId,
    /// State observed after restart.
    pub state: TransactionState,
    /// Conservative recovery classification.
    pub action: RecoveryAction,
}

/// Journal and durable-state failure.
#[derive(Debug, Error)]
pub enum JournalError {
    /// `SQLite` failed a persistence operation.
    #[error("journal database operation failed")]
    Database(#[source] rusqlite::Error),
    /// JSON serialization or deserialization failed.
    #[error("journal JSON serialization failed")]
    Serialization(#[source] serde_json::Error),
    /// Canonical JSON serialization failed.
    #[error("journal canonicalization failed")]
    Canonical(#[source] veyra_protocol::CanonicalError),
    /// A filesystem operation failed.
    #[error("could not {operation} at {path}")]
    Io {
        /// Safe operation description.
        operation: &'static str,
        /// Path involved.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The append-only hash chain is corrupt or has a missing link.
    #[error("journal integrity verification failed near sequence {sequence:?}: {reason}")]
    Corrupt {
        /// First sequence with invalid evidence.
        sequence: Option<u64>,
        /// Safe reason.
        reason: String,
    },
    /// An immutable object ID was reused with different content.
    #[error("immutable {kind} object `{id}` already has different content")]
    ObjectConflict {
        /// Object class.
        kind: String,
        /// Stable identifier.
        id: String,
    },
    /// Requested durable object is absent.
    #[error("{kind} object `{id}` was not found")]
    NotFound {
        /// Object class.
        kind: String,
        /// Stable identifier.
        id: String,
    },
    /// Snapshot update observed a stale revision.
    #[error("transaction {transaction_id} did not have expected revision {expected}")]
    RevisionConflict {
        /// Transaction ID.
        transaction_id: TransactionId,
        /// Expected stored revision.
        expected: u64,
    },
    /// Capability could not be atomically consumed.
    #[error("capability {0} is missing, revoked, or exhausted")]
    CapabilityUnavailable(CapabilityId),
    /// Approval nonce already authorized an execution.
    #[error("approval nonce has already been consumed")]
    ApprovalReplay,
    /// A public page cursor or page size is malformed or outside hard limits.
    #[error("invalid pagination request: {0}")]
    InvalidCursor(&'static str),
    /// Receipt authentication is invalid.
    #[error("receipt authentication is invalid")]
    ForgedReceipt,
    /// A process-local connection mutex was poisoned.
    #[error("journal connection lock was poisoned")]
    Poisoned,
    /// Persisted state contradicted a kernel invariant.
    #[error("journal invariant failed: {0}")]
    Invariant(String),
}

fn integrity_verification_failure(
    error: JournalError,
    events_checked: u64,
    area: &'static str,
) -> Result<AuditVerification, JournalError> {
    let (message, first_invalid_sequence) = match error {
        JournalError::Corrupt { sequence, reason } => (reason, sequence),
        JournalError::Invariant(reason) => (reason, None),
        JournalError::Serialization(_) => (format!("{area} contain malformed JSON"), None),
        JournalError::Canonical(_) => (format!("{area} cannot be canonically verified"), None),
        JournalError::ForgedReceipt => (
            format!("{area} contain forged authentication evidence"),
            None,
        ),
        error => return Err(error),
    };
    let events_checked = first_invalid_sequence
        .filter(|_| events_checked == 0)
        .map_or(events_checked, |sequence| sequence.saturating_sub(1));
    Ok(AuditVerification {
        valid: false,
        events_checked,
        first_invalid_sequence,
        message,
    })
}

fn initialize(connection: &Connection, durable: bool) -> Result<(), JournalError> {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(JournalError::Database)?;
    if durable {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(JournalError::Database)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(JournalError::Database)?;
    }
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(JournalError::Database)?;
    connection
        .execute_batch(DATABASE_SCHEMA)
        .map_err(JournalError::Database)?;
    let existing: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(JournalError::Database)?;
    match existing {
        None => {
            connection
                .execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![DATABASE_SCHEMA_VERSION],
                )
                .map_err(JournalError::Database)?;
        }
        Some(version) if version == DATABASE_SCHEMA_VERSION => {}
        Some(version) => {
            return Err(JournalError::Invariant(format!(
                "unsupported database schema version `{version}`"
            )));
        }
    }
    let latest: Option<(i64, String)> = connection
        .query_row(
            "SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    let (count, head) = latest.map_or((0_i64, GENESIS_HASH.to_owned()), |value| value);
    connection
        .execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES (?1, ?2)",
            params![AUDIT_COUNT_KEY, count.to_string()],
        )
        .map_err(JournalError::Database)?;
    connection
        .execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES (?1, ?2)",
            params![AUDIT_HEAD_KEY, head],
        )
        .map_err(JournalError::Database)?;
    Ok(())
}

fn load_or_create_key(path: &Path) -> Result<[u8; 32], JournalError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| JournalError::Io {
            operation: "create receipt key directory",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            validate_private_key_file(path)?;
            let mut key = [0_u8; 32];
            file.read_exact(&mut key)
                .map_err(|source| JournalError::Io {
                    operation: "read receipt key",
                    path: path.to_path_buf(),
                    source,
                })?;
            let mut extra = [0_u8; 1];
            if file.read(&mut extra).map_err(|source| JournalError::Io {
                operation: "validate receipt key",
                path: path.to_path_buf(),
                source,
            })? != 0
            {
                return Err(JournalError::Invariant(
                    "receipt key must contain exactly 32 bytes".into(),
                ));
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let random_material = format!(
                "{}:{}:{}",
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            );
            let key: [u8; 32] = Sha256::digest(random_material.as_bytes()).into();
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|source| JournalError::Io {
                operation: "create receipt key",
                path: path.to_path_buf(),
                source,
            })?;
            file.write_all(&key).map_err(|source| JournalError::Io {
                operation: "write receipt key",
                path: path.to_path_buf(),
                source,
            })?;
            file.sync_all().map_err(|source| JournalError::Io {
                operation: "sync receipt key",
                path: path.to_path_buf(),
                source,
            })?;
            Ok(key)
        }
        Err(source) => Err(JournalError::Io {
            operation: "open receipt key",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_private_key_file(path: &Path) -> Result<(), JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| JournalError::Io {
        operation: "inspect receipt key",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JournalError::Invariant(
            "receipt key must be a regular, non-symlink file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JournalError::Invariant(
                "receipt key permissions must deny group and other access".into(),
            ));
        }
    }
    Ok(())
}

fn append_event_in_transaction(
    sql: &SqlTransaction<'_>,
    transaction_id: Option<TransactionId>,
    event_type: &str,
    causal_parent: Option<&str>,
    payload: Value,
) -> Result<AuditEvent, JournalError> {
    let payload = validate_audit_envelope(event_type, causal_parent, payload)?;
    let latest: Option<(i64, String)> = sql
        .query_row(
            "SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    let (anchored_count, anchored_head) = audit_anchor(sql)?;
    let latest_matches_anchor = match &latest {
        Some((sequence, hash)) => {
            u64::try_from(*sequence).ok() == Some(anchored_count) && hash == &anchored_head
        }
        None => anchored_count == 0 && anchored_head == GENESIS_HASH,
    };
    if !latest_matches_anchor {
        return Err(JournalError::Corrupt {
            sequence: latest
                .as_ref()
                .and_then(|(sequence, _)| u64::try_from(*sequence).ok()),
            reason: "audit tail disagrees with its local anchor".into(),
        });
    }
    let (sequence, previous_hash) = match latest {
        Some((sequence, hash)) => (
            u64::try_from(sequence)
                .map_err(|_| JournalError::Invariant("negative audit sequence".into()))?
                .checked_add(1)
                .ok_or_else(|| JournalError::Invariant("audit sequence overflow".into()))?,
            hash,
        ),
        None => (1, GENESIS_HASH.to_owned()),
    };
    let recorded_at = Utc::now();
    let id = AuditEventId::new();
    let hash = event_hash(
        id,
        transaction_id,
        sequence,
        event_type,
        causal_parent,
        &payload,
        &previous_hash,
        recorded_at,
    )?;
    let event = AuditEvent {
        id,
        transaction_id,
        sequence,
        event_type: event_type.to_owned(),
        causal_parent: causal_parent.map(str::to_owned),
        payload,
        previous_hash,
        hash,
        recorded_at,
    };
    sql.execute(
        "INSERT INTO audit_events(sequence, id, transaction_id, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            i64_from_u64(event.sequence)?,
            event.id.to_string(),
            event.transaction_id.map(|id| id.to_string()),
            event.event_type,
            event.causal_parent,
            serde_json::to_string(&event.payload).map_err(JournalError::Serialization)?,
            event.previous_hash,
            event.hash,
            event.recorded_at.to_rfc3339()
        ],
    )
    .map_err(JournalError::Database)?;
    sql.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![event.sequence.to_string(), AUDIT_COUNT_KEY],
    )
    .map_err(JournalError::Database)?;
    sql.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![event.hash, AUDIT_HEAD_KEY],
    )
    .map_err(JournalError::Database)?;
    Ok(event)
}

fn validate_audit_envelope(
    event_type: &str,
    causal_parent: Option<&str>,
    payload: Value,
) -> Result<Value, JournalError> {
    if event_type.is_empty()
        || event_type.len() > 128
        || !event_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
        || causal_parent.is_some_and(|value| {
            value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
        })
    {
        return Err(JournalError::Invariant(
            "audit event type or causal parent is malformed".into(),
        ));
    }
    let payload = redact_value(payload);
    if !json_value_within_audit_bounds(&payload)
        || serde_json::to_vec(&payload)
            .map_err(JournalError::Serialization)?
            .len()
            > MAXIMUM_AUDIT_PAYLOAD_BYTES
    {
        return Err(JournalError::Invariant(
            "audit event payload exceeds structural limits".into(),
        ));
    }
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn event_hash(
    id: AuditEventId,
    transaction_id: Option<TransactionId>,
    sequence: u64,
    event_type: &str,
    causal_parent: Option<&str>,
    payload: &Value,
    previous_hash: &str,
    recorded_at: DateTime<Utc>,
) -> Result<String, JournalError> {
    canonical_digest(&json!({
        "id": id,
        "transaction_id": transaction_id,
        "sequence": sequence,
        "event_type": event_type,
        "causal_parent": causal_parent,
        "payload": payload,
        "previous_hash": previous_hash,
        "recorded_at": recorded_at,
    }))
    .map_err(JournalError::Canonical)
}

fn read_events(
    connection: &Connection,
    transaction_id: Option<TransactionId>,
) -> Result<Vec<AuditEvent>, JournalError> {
    let mut statement = if transaction_id.is_some() {
        connection
            .prepare("SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events WHERE transaction_id = ?1 ORDER BY sequence")
            .map_err(JournalError::Database)?
    } else {
        connection
            .prepare("SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events ORDER BY sequence")
            .map_err(JournalError::Database)?
    };
    let mut rows = if let Some(id) = transaction_id {
        statement
            .query(params![id.to_string()])
            .map_err(JournalError::Database)?
    } else {
        statement.query([]).map_err(JournalError::Database)?
    };
    let mut events = Vec::new();
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        events.push(audit_event_from_row(row)?);
    }
    Ok(events)
}

fn audit_event_from_row(row: &Row<'_>) -> Result<AuditEvent, JournalError> {
    let id: String = row.get(0).map_err(JournalError::Database)?;
    let tx_id: Option<String> = row.get(1).map_err(JournalError::Database)?;
    let raw_sequence: i64 = row.get(2).map_err(JournalError::Database)?;
    let sequence = u64::try_from(raw_sequence).map_err(|_| JournalError::Corrupt {
        sequence: None,
        reason: "audit event has a negative sequence".into(),
    })?;
    let id = id.parse().map_err(|_| JournalError::Corrupt {
        sequence: Some(sequence),
        reason: "audit event has a malformed ID".into(),
    })?;
    let transaction_id =
        tx_id
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| JournalError::Corrupt {
                sequence: Some(sequence),
                reason: "audit event has a malformed transaction ID".into(),
            })?;
    let payload_json: String = row.get(5).map_err(JournalError::Database)?;
    let payload = serde_json::from_str(&payload_json).map_err(|_| JournalError::Corrupt {
        sequence: Some(sequence),
        reason: "audit event contains malformed JSON".into(),
    })?;
    let recorded_at: String = row.get(8).map_err(JournalError::Database)?;
    let recorded_at = DateTime::parse_from_rfc3339(&recorded_at)
        .map_err(|_| JournalError::Corrupt {
            sequence: Some(sequence),
            reason: "audit event has a malformed timestamp".into(),
        })?
        .with_timezone(&Utc);
    Ok(AuditEvent {
        id,
        transaction_id,
        sequence,
        event_type: row.get(3).map_err(JournalError::Database)?,
        causal_parent: row.get(4).map_err(JournalError::Database)?,
        payload,
        previous_hash: row.get(6).map_err(JournalError::Database)?,
        hash: row.get(7).map_err(JournalError::Database)?,
        recorded_at,
    })
}

fn audit_anchor(connection: &Connection) -> Result<(u64, String), JournalError> {
    let count: String = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![AUDIT_COUNT_KEY],
            |row| row.get(0),
        )
        .map_err(JournalError::Database)?;
    let head: String = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![AUDIT_HEAD_KEY],
            |row| row.get(0),
        )
        .map_err(JournalError::Database)?;
    let count = count.parse::<u64>().map_err(|_| JournalError::Corrupt {
        sequence: None,
        reason: "audit event-count anchor is malformed".into(),
    })?;
    Ok((count, head))
}

fn verify_events_streaming(connection: &Connection) -> Result<AuditVerification, JournalError> {
    let (expected_count, expected_head) = audit_anchor(connection)?;
    let mut statement = connection
        .prepare("SELECT id, transaction_id, sequence, event_type, causal_parent, payload_json, previous_hash, hash, recorded_at FROM audit_events ORDER BY sequence")
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    let mut previous = GENESIS_HASH.to_owned();
    let mut observed_count = 0_u64;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let event = audit_event_from_row(row)?;
        let expected_sequence = observed_count.saturating_add(1);
        if event.sequence != expected_sequence || event.previous_hash != previous {
            return Ok(AuditVerification {
                valid: false,
                events_checked: observed_count,
                first_invalid_sequence: Some(event.sequence),
                message: "missing sequence or previous-hash link".into(),
            });
        }
        let recomputed = event_hash(
            event.id,
            event.transaction_id,
            event.sequence,
            &event.event_type,
            event.causal_parent.as_deref(),
            &event.payload,
            &event.previous_hash,
            event.recorded_at,
        );
        if !matches!(recomputed, Ok(ref hash) if hash == &event.hash) {
            return Ok(AuditVerification {
                valid: false,
                events_checked: observed_count,
                first_invalid_sequence: Some(event.sequence),
                message: "event content digest mismatch".into(),
            });
        }
        previous.clone_from(&event.hash);
        observed_count = expected_sequence;
    }
    if observed_count != expected_count || previous != expected_head {
        return Ok(AuditVerification {
            valid: false,
            events_checked: observed_count,
            first_invalid_sequence: observed_count.checked_add(1),
            message: "journal tail disagrees with its local count/hash anchor".into(),
        });
    }
    Ok(AuditVerification {
        valid: true,
        events_checked: observed_count,
        first_invalid_sequence: None,
        message: "journal hash chain is valid".into(),
    })
}

fn get_object_from_connection<T: DeserializeOwned + Serialize>(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<T, JournalError> {
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT canonical_json, digest FROM objects WHERE kind = ?1 AND id = ?2",
            params![kind, id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    let Some((serialized, digest)) = row else {
        if latest_object_digest_optional(connection, kind, id)?.is_some() {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "immutable {kind} object `{id}` is missing from its snapshot table"
                ),
            });
        }
        return Err(JournalError::NotFound {
            kind: kind.to_owned(),
            id: id.to_owned(),
        });
    };
    deserialize_verified_object(connection, kind, id, &serialized, &digest)
}

fn objects_by_json_field_from_connection<T: DeserializeOwned + Serialize>(
    connection: &Connection,
    kind: &str,
    field: &'static str,
    value: &str,
) -> Result<Vec<T>, JournalError> {
    let query = match field {
        "$.transaction_id" => {
            "SELECT id, canonical_json, digest FROM objects WHERE kind = ?1 AND json_extract(canonical_json, '$.transaction_id') = ?2 ORDER BY created_at, id"
        }
        "$.effect_id" => {
            "SELECT id, canonical_json, digest FROM objects WHERE kind = ?1 AND json_extract(canonical_json, '$.effect_id') = ?2 ORDER BY created_at, id"
        }
        _ => {
            return Err(JournalError::Invariant(
                "unsupported object index field".into(),
            ));
        }
    };
    let mut statement = connection.prepare(query).map_err(JournalError::Database)?;
    let rows = statement
        .query_map(params![kind, value], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(JournalError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(JournalError::Database)?;
    drop(statement);
    rows.into_iter()
        .map(|(id, serialized, digest)| {
            deserialize_verified_object(connection, kind, &id, &serialized, &digest)
        })
        .collect()
}

fn transaction_from_connection(
    connection: &Connection,
    id: TransactionId,
) -> Result<Transaction, JournalError> {
    let (stored_id, revision, state, serialized, updated_at): (
        String,
        i64,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT id, revision, state, json, updated_at FROM transactions WHERE id = ?1",
            params![id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(JournalError::Database)?
        .ok_or_else(|| JournalError::NotFound {
            kind: "transaction".into(),
            id: id.to_string(),
        })?;
    let expected_digest = latest_transaction_snapshot_digest(connection, &stored_id)?;
    deserialize_transaction_snapshot(
        &stored_id,
        revision,
        &state,
        &serialized,
        &updated_at,
        &expected_digest,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApprovalConsumptionBinding {
    grant_id: String,
    consumed_at: String,
}

fn verify_approval_consumptions(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare("SELECT nonce, grant_id, consumed_at FROM consumed_approval_nonces ORDER BY nonce")
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let nonce = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let grant_id = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let consumed_at = row.get::<_, String>(2).map_err(JournalError::Database)?;
        validate_approval_consumption(&nonce, &grant_id, &consumed_at)?;
        let binding = latest_approval_consumption(connection, &nonce)?.ok_or_else(|| {
            JournalError::Corrupt {
                sequence: None,
                reason: "approval nonce replay state has no audit binding".into(),
            }
        })?;
        if binding.grant_id != grant_id || binding.consumed_at != consumed_at {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "approval nonce replay state disagrees with its audit binding".into(),
            });
        }
    }
    drop(rows);
    drop(statement);

    let mut statement = connection
        .prepare(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('approval.consumed', 'approval.consumption_anchored') ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    let mut seen = HashSet::new();
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let payload: String = row.get(0).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let nonce = payload
            .get("approval_nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "approval consumption event has a malformed nonce".into(),
            })?;
        if !seen.insert(nonce.to_owned()) {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "approval nonce has multiple consumption events".into(),
            });
        }
        let binding = approval_consumption_from_payload(&payload, nonce)?;
        let persisted: Option<(String, String)> = connection
            .query_row(
                "SELECT grant_id, consumed_at FROM consumed_approval_nonces WHERE nonce = ?1",
                params![nonce],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if persisted.as_ref() != Some(&(binding.grant_id.clone(), binding.consumed_at.clone())) {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "audit-bound approval consumption has no matching replay state".into(),
            });
        }
    }
    Ok(())
}

fn latest_approval_consumption(
    connection: &Connection,
    nonce: &str,
) -> Result<Option<ApprovalConsumptionBinding>, JournalError> {
    let payload: Option<String> = connection
        .query_row(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('approval.consumed', 'approval.consumption_anchored') AND json_extract(payload_json, '$.approval_nonce') = ?1 ORDER BY sequence DESC LIMIT 1",
            params![nonce],
            |row| row.get(0),
        )
        .optional()
        .map_err(JournalError::Database)?;
    payload
        .map(|payload| {
            let payload: Value =
                serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
            approval_consumption_from_payload(&payload, nonce)
        })
        .transpose()
}

fn approval_consumption_from_payload(
    payload: &Value,
    expected_nonce: &str,
) -> Result<ApprovalConsumptionBinding, JournalError> {
    let nonce = payload
        .get("approval_nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "approval consumption event has a malformed nonce".into(),
        })?;
    let grant_id = payload
        .get("grant_id")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "approval consumption event has a malformed grant ID".into(),
        })?;
    let consumed_at = payload
        .get("consumed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "approval consumption event has a malformed timestamp".into(),
        })?;
    if nonce != expected_nonce {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "approval consumption event disagrees with its indexed nonce".into(),
        });
    }
    validate_approval_consumption(nonce, grant_id, consumed_at)?;
    Ok(ApprovalConsumptionBinding {
        grant_id: grant_id.to_owned(),
        consumed_at: consumed_at.to_owned(),
    })
}

fn validate_approval_consumption(
    nonce: &str,
    grant_id: &str,
    consumed_at: &str,
) -> Result<(), JournalError> {
    if nonce.is_empty()
        || nonce.len() > 256
        || nonce.bytes().any(|byte| byte.is_ascii_control())
        || grant_id.parse::<ApprovalGrantId>().is_err()
        || DateTime::parse_from_rfc3339(consumed_at).is_err()
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "approval nonce replay state is malformed".into(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapabilityBinding {
    digest: String,
    uses: u32,
    revoked: bool,
}

fn verify_capability_snapshots(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare("SELECT id, nonce, json, uses, revoked FROM capabilities ORDER BY id")
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let id = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let nonce = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let serialized = row.get::<_, String>(2).map_err(JournalError::Database)?;
        let uses = row.get::<_, i64>(3).map_err(JournalError::Database)?;
        let revoked = row.get::<_, bool>(4).map_err(JournalError::Database)?;
        verify_capability_row(connection, &id, &nonce, &serialized, uses, revoked)?;
    }
    drop(rows);
    drop(statement);

    let mut statement = connection
        .prepare(
            "SELECT event_type, payload_json FROM audit_events WHERE event_type IN ('capability.issued', 'capability.consumed', 'capability.revoked', 'capability.snapshot_anchored') ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    let mut bound_ids = HashSet::new();
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let event_type = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let payload = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let raw_id = payload
            .get("capability_id")
            .and_then(Value::as_str)
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "capability binding event has a malformed ID".into(),
            })?;
        let id = raw_id
            .parse::<CapabilityId>()
            .map_err(|_| JournalError::Corrupt {
                sequence: None,
                reason: "capability binding event has a malformed ID".into(),
            })?;
        if id.to_string() != raw_id {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "capability binding event has a non-canonical ID".into(),
            });
        }
        let uses = payload
            .get("capability_uses")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "capability binding event has malformed use facts".into(),
            })?;
        let revoked = payload
            .get("capability_revoked")
            .and_then(Value::as_bool)
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "capability binding event has malformed revocation facts".into(),
            })?;
        let digest = payload.get("capability_digest");
        match event_type.as_str() {
            "capability.issued"
                if uses == 0
                    && !revoked
                    && digest.and_then(Value::as_str).is_some_and(valid_sha256_hex) => {}
            "capability.snapshot_anchored"
                if digest.and_then(Value::as_str).is_some_and(valid_sha256_hex) => {}
            "capability.consumed" if !revoked && digest.is_none() => {}
            "capability.revoked" if revoked && digest.is_none() => {}
            _ => {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: "capability binding event has inconsistent semantic facts".into(),
                });
            }
        }
        bound_ids.insert(id);
    }
    drop(rows);
    drop(statement);
    for id in bound_ids {
        let exists = connection
            .query_row(
                "SELECT 1 FROM capabilities WHERE id = ?1",
                params![id.to_string()],
                |_| Ok(()),
            )
            .optional()
            .map_err(JournalError::Database)?
            .is_some();
        if !exists {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "audit-bound capability snapshot `{id}` is missing from its state table"
                ),
            });
        }
    }
    Ok(())
}

fn verify_capability_row(
    connection: &Connection,
    stored_id: &str,
    stored_nonce: &str,
    serialized: &str,
    stored_uses: i64,
    stored_revoked: bool,
) -> Result<(Capability, CapabilityFacts), JournalError> {
    let capability = deserialize_capability_index(stored_id, stored_nonce, serialized)?;
    let facts = capability_facts(stored_uses, stored_revoked, stored_id)?;
    let binding =
        latest_capability_binding(connection, stored_id)?.ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: format!("capability snapshot `{stored_id}` has no audit-bound state"),
        })?;
    let actual_digest = canonical_digest(&capability).map_err(JournalError::Canonical)?;
    if actual_digest != binding.digest
        || facts.uses != binding.uses
        || facts.revoked != binding.revoked
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!(
                "capability snapshot `{stored_id}` disagrees with its audit-bound state"
            ),
        });
    }
    Ok((capability, facts))
}

fn deserialize_capability_index(
    stored_id: &str,
    stored_nonce: &str,
    serialized: &str,
) -> Result<Capability, JournalError> {
    let capability: Capability =
        serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    if capability.id.to_string() != stored_id || capability.nonce != stored_nonce {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("capability snapshot `{stored_id}` disagrees with indexed identity"),
        });
    }
    Ok(capability)
}

fn capability_facts(
    stored_uses: i64,
    stored_revoked: bool,
    stored_id: &str,
) -> Result<CapabilityFacts, JournalError> {
    Ok(CapabilityFacts {
        uses: u32::try_from(stored_uses).map_err(|_| JournalError::Corrupt {
            sequence: None,
            reason: format!("capability snapshot `{stored_id}` has an invalid use count"),
        })?,
        revoked: stored_revoked,
    })
}

fn latest_capability_binding(
    connection: &Connection,
    capability_id: &str,
) -> Result<Option<CapabilityBinding>, JournalError> {
    let mut statement = connection
        .prepare(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('capability.issued', 'capability.consumed', 'capability.revoked', 'capability.snapshot_anchored') AND json_extract(payload_json, '$.capability_id') = ?1 ORDER BY sequence DESC",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement
        .query(params![capability_id])
        .map_err(JournalError::Database)?;
    let mut digest = None;
    let mut facts = None;
    let mut saw_binding_field = false;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let payload: String = row.get(0).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let has_digest = payload.get("capability_digest").is_some();
        let has_uses = payload.get("capability_uses").is_some();
        let has_revoked = payload.get("capability_revoked").is_some();
        if !has_digest && !has_uses && !has_revoked {
            continue;
        }
        saw_binding_field = true;
        if digest.is_none() && has_digest {
            let value = payload["capability_digest"]
                .as_str()
                .filter(|value| valid_sha256_hex(value))
                .ok_or_else(|| JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "capability snapshot `{capability_id}` has a malformed audit digest"
                    ),
                })?;
            digest = Some(value.to_ascii_lowercase());
        }
        if facts.is_none() && (has_uses || has_revoked) {
            if !has_uses || !has_revoked {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "capability snapshot `{capability_id}` has incomplete audit facts"
                    ),
                });
            }
            let uses = payload["capability_uses"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "capability snapshot `{capability_id}` has malformed audit facts"
                    ),
                })?;
            let revoked =
                payload["capability_revoked"]
                    .as_bool()
                    .ok_or_else(|| JournalError::Corrupt {
                        sequence: None,
                        reason: format!(
                            "capability snapshot `{capability_id}` has malformed audit facts"
                        ),
                    })?;
            facts = Some((uses, revoked));
        }
        if digest.is_some() && facts.is_some() {
            break;
        }
    }
    match (digest, facts, saw_binding_field) {
        (Some(digest), Some((uses, revoked)), _) => Ok(Some(CapabilityBinding {
            digest,
            uses,
            revoked,
        })),
        (None, None, false) => Ok(None),
        _ => Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("capability snapshot `{capability_id}` has incomplete audit binding"),
        }),
    }
}

fn verify_transaction_snapshots(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare("SELECT id, revision, state, json, updated_at FROM transactions ORDER BY id")
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let id = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let revision = row.get::<_, i64>(1).map_err(JournalError::Database)?;
        let state = row.get::<_, String>(2).map_err(JournalError::Database)?;
        let serialized = row.get::<_, String>(3).map_err(JournalError::Database)?;
        let updated_at = row.get::<_, String>(4).map_err(JournalError::Database)?;
        let expected_digest = latest_transaction_snapshot_digest(connection, &id)?;
        deserialize_transaction_snapshot(
            &id,
            revision,
            &state,
            &serialized,
            &updated_at,
            &expected_digest,
        )?;
    }
    drop(rows);
    drop(statement);

    let mut statement = connection
        .prepare(
            "SELECT transaction_id, payload_json FROM audit_events WHERE json_type(payload_json, '$.snapshot_digest') IS NOT NULL ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    let mut bound_ids = HashSet::new();
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let raw_id = row
            .get::<_, Option<String>>(0)
            .map_err(JournalError::Database)?
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "transaction snapshot binding has no transaction ID".into(),
            })?;
        let id = raw_id
            .parse::<TransactionId>()
            .map_err(|_| JournalError::Corrupt {
                sequence: None,
                reason: "transaction snapshot binding has a malformed transaction ID".into(),
            })?;
        if id.to_string() != raw_id {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "transaction snapshot binding has a non-canonical transaction ID".into(),
            });
        }
        let payload = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        if !payload
            .get("snapshot_digest")
            .and_then(Value::as_str)
            .is_some_and(valid_sha256_hex)
        {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "transaction snapshot binding has a malformed digest".into(),
            });
        }
        bound_ids.insert(id);
    }
    drop(rows);
    drop(statement);
    for id in bound_ids {
        if let Err(error) = transaction_from_connection(connection, id) {
            return match error {
                JournalError::NotFound { .. } => Err(JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "audit-bound transaction snapshot `{id}` is missing from its state table"
                    ),
                }),
                other => Err(other),
            };
        }
    }
    Ok(())
}

fn deserialize_transaction_snapshot(
    stored_id: &str,
    stored_revision: i64,
    stored_state: &str,
    serialized: &str,
    stored_updated_at: &str,
    expected_digest: &str,
) -> Result<Transaction, JournalError> {
    let transaction = deserialize_transaction_snapshot_index(
        stored_id,
        stored_revision,
        stored_state,
        serialized,
        stored_updated_at,
    )?;
    let actual_digest = canonical_digest(&transaction).map_err(JournalError::Canonical)?;
    if actual_digest != expected_digest {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!(
                "transaction snapshot `{stored_id}` disagrees with its audit-bound digest"
            ),
        });
    }
    Ok(transaction)
}

fn deserialize_transaction_snapshot_index(
    stored_id: &str,
    stored_revision: i64,
    stored_state: &str,
    serialized: &str,
    stored_updated_at: &str,
) -> Result<Transaction, JournalError> {
    let transaction: Transaction =
        serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    let revision = u64::try_from(stored_revision)
        .map_err(|_| JournalError::Invariant("transaction revision is negative".into()))?;
    let indexed_updated_at = DateTime::parse_from_rfc3339(stored_updated_at)
        .map_err(|_| JournalError::Invariant("invalid indexed transaction timestamp".into()))?
        .with_timezone(&Utc);
    if transaction.id.to_string() != stored_id
        || transaction.revision != revision
        || state_name(transaction.state) != stored_state
        || transaction.updated_at != indexed_updated_at
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("transaction snapshot `{stored_id}` disagrees with indexed state"),
        });
    }
    Ok(transaction)
}

fn latest_transaction_snapshot_digest(
    connection: &Connection,
    transaction_id: &str,
) -> Result<String, JournalError> {
    latest_transaction_snapshot_digest_optional(connection, transaction_id)?.ok_or_else(|| {
        JournalError::Corrupt {
            sequence: None,
            reason: format!("transaction snapshot `{transaction_id}` has no audit-bound digest"),
        }
    })
}

fn latest_transaction_snapshot_digest_optional(
    connection: &Connection,
    transaction_id: &str,
) -> Result<Option<String>, JournalError> {
    let mut statement = connection
        .prepare(
            "SELECT payload_json FROM audit_events WHERE transaction_id = ?1 ORDER BY sequence DESC",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement
        .query(params![transaction_id])
        .map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let payload: String = row.get(0).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        if let Some(digest) = payload.get("snapshot_digest") {
            let digest = digest.as_str().ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "transaction snapshot `{transaction_id}` has a malformed audit digest"
                ),
            })?;
            if !valid_sha256_hex(digest) {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: format!(
                        "transaction snapshot `{transaction_id}` has a malformed audit digest"
                    ),
                });
            }
            return Ok(Some(digest.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

fn bind_snapshot_digest(mut payload: Value, digest: String) -> Value {
    if let Value::Object(map) = &mut payload {
        map.insert("snapshot_digest".into(), Value::String(digest));
        payload
    } else {
        json!({"details": payload, "snapshot_digest": digest})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IdempotencyBinding {
    effect_digest: String,
    status: String,
    receipt_digest: Option<String>,
    updated_at: String,
}

fn verify_idempotency_snapshots(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare(
            "SELECT adapter, key, effect_digest, status, receipt_json, updated_at FROM idempotency ORDER BY adapter, key",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let adapter = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let key = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let effect_digest = row.get::<_, String>(2).map_err(JournalError::Database)?;
        let status = row.get::<_, String>(3).map_err(JournalError::Database)?;
        let receipt_json = row
            .get::<_, Option<String>>(4)
            .map_err(JournalError::Database)?;
        let updated_at = row.get::<_, String>(5).map_err(JournalError::Database)?;
        verify_idempotency_row(
            connection,
            &adapter,
            &key,
            &effect_digest,
            &status,
            receipt_json.as_deref(),
            &updated_at,
        )?;
    }
    drop(rows);
    drop(statement);

    let mut statement = connection
        .prepare(
            "SELECT event_type, payload_json FROM audit_events AS current WHERE event_type IN ('idempotency.reserved', 'idempotency.completed', 'idempotency.unknown', 'idempotency.snapshot_anchored') AND NOT EXISTS (SELECT 1 FROM audit_events AS newer WHERE newer.event_type IN ('idempotency.reserved', 'idempotency.completed', 'idempotency.unknown', 'idempotency.snapshot_anchored') AND json_extract(newer.payload_json, '$.idempotency_adapter') = json_extract(current.payload_json, '$.idempotency_adapter') AND json_extract(newer.payload_json, '$.idempotency_key') = json_extract(current.payload_json, '$.idempotency_key') AND newer.sequence > current.sequence) ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let event_type = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let payload = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let adapter = payload
            .get("idempotency_adapter")
            .and_then(Value::as_str)
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "idempotency event has a malformed adapter".into(),
            })?;
        let key = payload
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or_else(|| JournalError::Corrupt {
                sequence: None,
                reason: "idempotency event has a malformed key".into(),
            })?;
        let binding = idempotency_binding_from_payload(&payload, adapter, key)?;
        validate_idempotency_event_type(&event_type, &binding.status)?;
        let persisted: Option<(String, String, Option<String>, String)> = connection
            .query_row(
                "SELECT effect_digest, status, receipt_json, updated_at FROM idempotency WHERE adapter = ?1 AND key = ?2",
                params![adapter, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((effect_digest, status, receipt_json, updated_at)) = persisted else {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "audit-bound idempotency state is missing from its snapshot table".into(),
            });
        };
        let receipt_digest = idempotency_receipt_digest(receipt_json.as_deref())?;
        if binding.effect_digest != effect_digest
            || binding.status != status
            || binding.receipt_digest != receipt_digest
            || binding.updated_at != updated_at
        {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "idempotency snapshot disagrees with its audit-bound state".into(),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_idempotency_row(
    connection: &Connection,
    adapter: &str,
    key: &str,
    effect_digest: &str,
    status: &str,
    receipt_json: Option<&str>,
    updated_at: &str,
) -> Result<(), JournalError> {
    validate_idempotency_row(
        adapter,
        key,
        effect_digest,
        status,
        receipt_json,
        updated_at,
    )?;
    let receipt_digest = idempotency_receipt_digest(receipt_json)?;
    let binding =
        latest_idempotency_binding_optional(connection, adapter, key)?.ok_or_else(|| {
            JournalError::Corrupt {
                sequence: None,
                reason: "idempotency snapshot has no audit-bound state".into(),
            }
        })?;
    if binding.effect_digest != effect_digest
        || binding.status != status
        || binding.receipt_digest != receipt_digest
        || binding.updated_at != updated_at
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "idempotency snapshot disagrees with its audit-bound state".into(),
        });
    }
    Ok(())
}

fn validate_idempotency_row(
    adapter: &str,
    key: &str,
    effect_digest: &str,
    status: &str,
    receipt_json: Option<&str>,
    updated_at: &str,
) -> Result<(), JournalError> {
    validate_idempotency_binding_fields(
        adapter,
        key,
        effect_digest,
        status,
        receipt_json.is_some(),
        updated_at,
    )?;
    if let Some(serialized) = receipt_json {
        let receipt: Receipt =
            serde_json::from_str(serialized).map_err(|_| JournalError::Corrupt {
                sequence: None,
                reason: "idempotency snapshot has a malformed receipt".into(),
            })?;
        if receipt.effect_digest != effect_digest {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "idempotency receipt disagrees with its effect digest".into(),
            });
        }
    }
    Ok(())
}

fn validate_idempotency_binding_fields(
    adapter: &str,
    key: &str,
    effect_digest: &str,
    status: &str,
    has_receipt: bool,
    updated_at: &str,
) -> Result<(), JournalError> {
    validate_idempotency_identity(adapter, key)?;
    if !valid_sha256_hex(effect_digest)
        || !matches!(status, "reserved" | "complete" | "unknown")
        || DateTime::parse_from_rfc3339(updated_at).is_err()
        || (status == "complete") != has_receipt
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "idempotency snapshot has malformed indexed state".into(),
        });
    }
    Ok(())
}

fn validate_idempotency_identity(adapter: &str, key: &str) -> Result<(), JournalError> {
    if adapter.is_empty()
        || adapter.len() > 128
        || adapter.bytes().any(|byte| byte.is_ascii_control())
        || key.is_empty()
        || key.len() > 256
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "idempotency identity is malformed".into(),
        });
    }
    Ok(())
}

fn validate_idempotency_arguments(
    adapter: &str,
    key: &str,
    effect_digest: &str,
) -> Result<(), JournalError> {
    validate_idempotency_identity(adapter, key)?;
    if !valid_sha256_hex(effect_digest) {
        return Err(JournalError::Invariant(
            "idempotency effect digest is not canonical SHA-256".into(),
        ));
    }
    Ok(())
}

fn idempotency_receipt_digest(receipt_json: Option<&str>) -> Result<Option<String>, JournalError> {
    receipt_json
        .map(|serialized| {
            let value: Value =
                serde_json::from_str(serialized).map_err(|_| JournalError::Corrupt {
                    sequence: None,
                    reason: "idempotency snapshot has a malformed receipt".into(),
                })?;
            canonical_digest(&value).map_err(JournalError::Canonical)
        })
        .transpose()
}

fn latest_idempotency_binding_optional(
    connection: &Connection,
    adapter: &str,
    key: &str,
) -> Result<Option<IdempotencyBinding>, JournalError> {
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT event_type, payload_json FROM audit_events WHERE event_type IN ('idempotency.reserved', 'idempotency.completed', 'idempotency.unknown', 'idempotency.snapshot_anchored') AND json_extract(payload_json, '$.idempotency_adapter') = ?1 AND json_extract(payload_json, '$.idempotency_key') = ?2 ORDER BY sequence DESC LIMIT 1",
            params![adapter, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    row.map(|(event_type, payload)| {
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let binding = idempotency_binding_from_payload(&payload, adapter, key)?;
        validate_idempotency_event_type(&event_type, &binding.status)?;
        Ok(binding)
    })
    .transpose()
}

fn idempotency_binding_from_payload(
    payload: &Value,
    expected_adapter: &str,
    expected_key: &str,
) -> Result<IdempotencyBinding, JournalError> {
    let adapter = payload
        .get("idempotency_adapter")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event has a malformed adapter".into(),
        })?;
    let key = payload
        .get("idempotency_key")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event has a malformed key".into(),
        })?;
    if adapter != expected_adapter || key != expected_key {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "idempotency audit binding disagrees with its indexed identity".into(),
        });
    }
    let effect_digest = payload
        .get("effect_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event has a malformed effect digest".into(),
        })?;
    let status = payload
        .get("idempotency_status")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event has a malformed status".into(),
        })?;
    let receipt_digest = match payload.get("receipt_digest") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if valid_sha256_hex(value) => Some(value.to_ascii_lowercase()),
        Some(_) => {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: "idempotency event has a malformed receipt digest".into(),
            });
        }
    };
    let updated_at = payload
        .get("idempotency_updated_at")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event has a malformed timestamp".into(),
        })?;
    validate_idempotency_binding_fields(
        adapter,
        key,
        effect_digest,
        status,
        receipt_digest.is_some(),
        updated_at,
    )?;
    Ok(IdempotencyBinding {
        effect_digest: effect_digest.to_owned(),
        status: status.to_owned(),
        receipt_digest,
        updated_at: updated_at.to_owned(),
    })
}

fn validate_idempotency_event_type(event_type: &str, status: &str) -> Result<(), JournalError> {
    if event_type != "idempotency.snapshot_anchored"
        && !matches!(
            (event_type, status),
            ("idempotency.reserved", "reserved")
                | ("idempotency.completed", "complete")
                | ("idempotency.unknown", "unknown")
        )
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "idempotency event type disagrees with its state".into(),
        });
    }
    Ok(())
}

fn idempotency_payload(
    adapter: &str,
    key: &str,
    effect_digest: &str,
    status: &str,
    receipt_digest: Option<&str>,
    updated_at: &str,
) -> Value {
    json!({
        "idempotency_adapter": adapter,
        "idempotency_key": key,
        "effect_digest": effect_digest,
        "idempotency_status": status,
        "receipt_digest": receipt_digest,
        "idempotency_updated_at": updated_at,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StageBinding {
    adapter: String,
    digest: String,
    status: String,
}

fn verify_staged_effects(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare(
            "SELECT transaction_id, effect_id, adapter, stage_json, status FROM staged_effects ORDER BY transaction_id, effect_id",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let transaction_id = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let effect_id = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let adapter = row.get::<_, String>(2).map_err(JournalError::Database)?;
        let serialized = row.get::<_, String>(3).map_err(JournalError::Database)?;
        let status = row.get::<_, String>(4).map_err(JournalError::Database)?;
        let transaction_id =
            transaction_id
                .parse::<TransactionId>()
                .map_err(|_| JournalError::Corrupt {
                    sequence: None,
                    reason: "staged effect has an invalid transaction ID".into(),
                })?;
        let effect_id =
            effect_id
                .parse::<veyra_protocol::EffectId>()
                .map_err(|_| JournalError::Corrupt {
                    sequence: None,
                    reason: "staged effect has an invalid effect ID".into(),
                })?;
        verify_stage_serialized(
            connection,
            transaction_id,
            effect_id,
            &adapter,
            &serialized,
            &status,
        )?;
    }
    drop(rows);
    drop(statement);

    let duplicate: Option<(String, String)> = connection
        .query_row(
            "SELECT transaction_id, json_extract(payload_json, '$.effect_id') FROM audit_events WHERE event_type IN ('stage.stored', 'stage.snapshot_anchored') GROUP BY transaction_id, json_extract(payload_json, '$.effect_id') HAVING COUNT(*) != 1 LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    if duplicate.is_some() {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "staged effect has multiple audit bindings".into(),
        });
    }

    let mut statement = connection
        .prepare(
            "SELECT transaction_id, payload_json FROM audit_events WHERE event_type IN ('stage.stored', 'stage.snapshot_anchored') ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let transaction_id = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let payload = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let transaction_id =
            transaction_id
                .parse::<TransactionId>()
                .map_err(|_| JournalError::Corrupt {
                    sequence: None,
                    reason: "stage binding event has an invalid transaction ID".into(),
                })?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let (effect_id, binding) = stage_binding_from_payload(&payload)?;
        let persisted: Option<(String, String, String)> = connection
            .query_row(
                "SELECT adapter, stage_json, status FROM staged_effects WHERE transaction_id = ?1 AND effect_id = ?2",
                params![transaction_id.to_string(), effect_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((adapter, serialized, status)) = persisted else {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "audit-bound stage for effect `{effect_id}` is missing from its snapshot table"
                ),
            });
        };
        if adapter != binding.adapter
            || status != binding.status
            || stage_actual_digest(&serialized)? != binding.digest
        {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "stage for effect `{effect_id}` disagrees with its audit-bound state"
                ),
            });
        }
    }
    Ok(())
}

fn verify_stage_serialized(
    connection: &Connection,
    transaction_id: TransactionId,
    effect_id: veyra_protocol::EffectId,
    adapter: &str,
    serialized: &str,
    status: &str,
) -> Result<(), JournalError> {
    validate_stage_index(adapter, status)?;
    let actual_digest = stage_actual_digest(serialized)?;
    let binding = latest_stage_binding_optional(connection, transaction_id, effect_id)?
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: format!("stage for effect `{effect_id}` has no audit-bound state"),
        })?;
    if binding.adapter != adapter || binding.digest != actual_digest || binding.status != status {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("stage for effect `{effect_id}` disagrees with its audit-bound state"),
        });
    }
    Ok(())
}

fn latest_stage_binding_optional(
    connection: &Connection,
    transaction_id: TransactionId,
    effect_id: veyra_protocol::EffectId,
) -> Result<Option<StageBinding>, JournalError> {
    let payload: Option<String> = connection
        .query_row(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('stage.stored', 'stage.snapshot_anchored') AND transaction_id = ?1 AND json_extract(payload_json, '$.effect_id') = ?2 ORDER BY sequence DESC LIMIT 1",
            params![transaction_id.to_string(), effect_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(JournalError::Database)?;
    payload
        .map(|payload| {
            let payload: Value =
                serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
            let (bound_effect_id, binding) = stage_binding_from_payload(&payload)?;
            if bound_effect_id != effect_id {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: "stage audit binding disagrees with its indexed effect".into(),
                });
            }
            Ok(binding)
        })
        .transpose()
}

fn stage_binding_from_payload(
    payload: &Value,
) -> Result<(veyra_protocol::EffectId, StageBinding), JournalError> {
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<veyra_protocol::EffectId>().ok())
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "stage binding event has a malformed effect ID".into(),
        })?;
    let adapter = payload
        .get("adapter")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "stage binding event has a malformed adapter".into(),
        })?;
    let digest = payload
        .get("stage_digest")
        .and_then(Value::as_str)
        .filter(|value| valid_sha256_hex(value))
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "stage binding event has a malformed digest".into(),
        })?;
    let status = payload
        .get("stage_status")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "stage binding event has a malformed status".into(),
        })?;
    validate_stage_index(adapter, status)?;
    Ok((
        effect_id,
        StageBinding {
            adapter: adapter.to_owned(),
            digest: digest.to_ascii_lowercase(),
            status: status.to_owned(),
        },
    ))
}

fn validate_stage_index(adapter: &str, status: &str) -> Result<(), JournalError> {
    if adapter.is_empty()
        || adapter.len() > 128
        || adapter.bytes().any(|byte| byte.is_ascii_control())
        || status != "staged"
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "staged effect has malformed indexed state".into(),
        });
    }
    Ok(())
}

fn stage_actual_digest(serialized: &str) -> Result<String, JournalError> {
    let value: Value = serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    canonical_digest(&value).map_err(JournalError::Canonical)
}

fn verify_object_snapshots(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare("SELECT kind, id, canonical_json, digest FROM objects ORDER BY kind, id")
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let kind = row.get::<_, String>(0).map_err(JournalError::Database)?;
        let id = row.get::<_, String>(1).map_err(JournalError::Database)?;
        let serialized = row.get::<_, String>(2).map_err(JournalError::Database)?;
        let digest = row.get::<_, String>(3).map_err(JournalError::Database)?;
        verify_object_serialized(connection, &kind, &id, &serialized, &digest)?;
    }
    drop(rows);
    drop(statement);

    let duplicate: Option<(String, String)> = connection
        .query_row(
            "SELECT json_extract(payload_json, '$.object_kind'), json_extract(payload_json, '$.object_id') FROM audit_events WHERE event_type IN ('object.stored', 'object.snapshot_anchored') GROUP BY json_extract(payload_json, '$.object_kind'), json_extract(payload_json, '$.object_id') HAVING COUNT(*) != 1 LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(JournalError::Database)?;
    if let Some((kind, id)) = duplicate {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("immutable {kind} object `{id}` has multiple audit bindings"),
        });
    }

    let mut statement = connection
        .prepare(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('object.stored', 'object.snapshot_anchored') ORDER BY sequence",
        )
        .map_err(JournalError::Database)?;
    let mut rows = statement.query([]).map_err(JournalError::Database)?;
    while let Some(row) = rows.next().map_err(JournalError::Database)? {
        let payload: String = row.get(0).map_err(JournalError::Database)?;
        let payload: Value = serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
        let (kind, id, expected_digest) = object_binding_from_payload(&payload)?;
        let persisted: Option<(String, String)> = connection
            .query_row(
                "SELECT canonical_json, digest FROM objects WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let Some((serialized, stored_digest)) = persisted else {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "audit-bound immutable {kind} object `{id}` is missing from its snapshot table"
                ),
            });
        };
        let actual_digest = object_actual_digest(kind, id, &serialized)?;
        if stored_digest != expected_digest || actual_digest != expected_digest {
            return Err(JournalError::Corrupt {
                sequence: None,
                reason: format!(
                    "immutable {kind} object `{id}` disagrees with its audit-bound digest"
                ),
            });
        }
    }
    Ok(())
}

fn verify_object_serialized(
    connection: &Connection,
    kind: &str,
    id: &str,
    serialized: &str,
    stored_digest: &str,
) -> Result<(), JournalError> {
    let actual_digest = object_actual_digest(kind, id, serialized)?;
    if actual_digest != stored_digest {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("immutable {kind} object `{id}` has a digest mismatch"),
        });
    }
    let expected_digest =
        latest_object_digest_optional(connection, kind, id)?.ok_or_else(|| {
            JournalError::Corrupt {
                sequence: None,
                reason: format!("immutable {kind} object `{id}` has no audit-bound digest"),
            }
        })?;
    if actual_digest != expected_digest {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("immutable {kind} object `{id}` disagrees with its audit-bound digest"),
        });
    }
    Ok(())
}

fn object_actual_digest(_kind: &str, _id: &str, serialized: &str) -> Result<String, JournalError> {
    let value: Value = serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    canonical_digest(&value).map_err(JournalError::Canonical)
}

fn latest_object_digest_optional(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<String>, JournalError> {
    let payload: Option<String> = connection
        .query_row(
            "SELECT payload_json FROM audit_events WHERE event_type IN ('object.stored', 'object.snapshot_anchored') AND json_extract(payload_json, '$.object_kind') = ?1 AND json_extract(payload_json, '$.object_id') = ?2 ORDER BY sequence DESC LIMIT 1",
            params![kind, id],
            |row| row.get(0),
        )
        .optional()
        .map_err(JournalError::Database)?;
    payload
        .map(|payload| {
            let payload: Value =
                serde_json::from_str(&payload).map_err(JournalError::Serialization)?;
            let (bound_kind, bound_id, digest) = object_binding_from_payload(&payload)?;
            if bound_kind != kind || bound_id != id {
                return Err(JournalError::Corrupt {
                    sequence: None,
                    reason: "immutable object audit binding disagrees with its index".into(),
                });
            }
            Ok(digest.to_owned())
        })
        .transpose()
}

fn object_binding_from_payload(payload: &Value) -> Result<(&str, &str, &str), JournalError> {
    let kind = payload
        .get("object_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "immutable object event has a malformed kind".into(),
        })?;
    let id = payload
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "immutable object event has a malformed ID".into(),
        })?;
    let digest = payload
        .get("object_digest")
        .and_then(Value::as_str)
        .filter(|value| valid_sha256_hex(value))
        .ok_or_else(|| JournalError::Corrupt {
            sequence: None,
            reason: "immutable object event has a malformed digest".into(),
        })?;
    if kind.is_empty()
        || kind.len() > 128
        || kind.chars().any(char::is_control)
        || id.is_empty()
        || id.len() > 512
        || id.chars().any(char::is_control)
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: "immutable object event has malformed identity bounds".into(),
        });
    }
    Ok((kind, id, digest))
}

fn deserialize_verified_object<T: DeserializeOwned + Serialize>(
    connection: &Connection,
    kind: &str,
    id: &str,
    serialized: &str,
    expected_digest: &str,
) -> Result<T, JournalError> {
    verify_object_serialized(connection, kind, id, serialized, expected_digest)?;
    let value: T = serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    Ok(value)
}

fn recovery_record(transaction: &Transaction) -> Result<RecoveryRecord, JournalError> {
    let action = match transaction.state {
        TransactionState::Draft
        | TransactionState::Planned
        | TransactionState::Preflighted
        | TransactionState::AwaitingApproval
        | TransactionState::Approved => RecoveryAction::ResumeSafe,
        TransactionState::Staged
        | TransactionState::Executing
        | TransactionState::Verifying
        | TransactionState::Compensating
        | TransactionState::ManualRecovery => RecoveryAction::ManualRecovery,
        TransactionState::Committed
        | TransactionState::Denied
        | TransactionState::Failed
        | TransactionState::RolledBack
        | TransactionState::PartiallyCompensated
        | TransactionState::Cancelled => {
            return Err(JournalError::Invariant(
                "terminal transaction passed recovery query".into(),
            ));
        }
    };
    Ok(RecoveryRecord {
        transaction_id: transaction.id,
        state: transaction.state,
        action,
    })
}

fn state_name(state: TransactionState) -> &'static str {
    match state {
        TransactionState::Draft => "draft",
        TransactionState::Planned => "planned",
        TransactionState::Preflighted => "preflighted",
        TransactionState::AwaitingApproval => "awaiting_approval",
        TransactionState::Approved => "approved",
        TransactionState::Staged => "staged",
        TransactionState::Executing => "executing",
        TransactionState::Verifying => "verifying",
        TransactionState::Committed => "committed",
        TransactionState::Denied => "denied",
        TransactionState::Failed => "failed",
        TransactionState::Compensating => "compensating",
        TransactionState::RolledBack => "rolled_back",
        TransactionState::PartiallyCompensated => "partially_compensated",
        TransactionState::Cancelled => "cancelled",
        TransactionState::ManualRecovery => "manual_recovery",
    }
}

fn i64_from_u64(value: u64) -> Result<i64, JournalError> {
    i64::try_from(value).map_err(|_| JournalError::Invariant("integer exceeds SQLite range".into()))
}

fn validate_page_limit(
    limit: usize,
    maximum: usize,
    kind: &'static str,
) -> Result<(), JournalError> {
    if limit == 0 || limit > maximum {
        return Err(JournalError::InvalidCursor(match kind {
            "transaction" => "transaction page limit is outside 1..=1000",
            "audit" => "audit page limit is outside 1..=10000",
            _ => "page limit is outside its allowed range",
        }));
    }
    Ok(())
}

fn encode_transaction_cursor(updated_at: &str, id: &str) -> String {
    encode_hex(format!("{updated_at}\0{id}").as_bytes())
}

fn decode_transaction_cursor(cursor: &str) -> Result<(String, String), JournalError> {
    if cursor.is_empty() || cursor.len() > 512 {
        return Err(JournalError::InvalidCursor(
            "transaction cursor has an invalid length",
        ));
    }
    let decoded = decode_hex(cursor)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(JournalError::InvalidCursor(
            "transaction cursor is not valid opaque data",
        ))?;
    let (updated_at, id) = decoded.split_once('\0').ok_or(JournalError::InvalidCursor(
        "transaction cursor is missing a key component",
    ))?;
    if updated_at.contains('\0')
        || id.contains('\0')
        || DateTime::parse_from_rfc3339(updated_at).is_err()
        || id.parse::<TransactionId>().is_err()
    {
        return Err(JournalError::InvalidCursor(
            "transaction cursor contains an invalid key",
        ));
    }
    Ok((updated_at.to_owned(), id.to_owned()))
}

fn decode_audit_cursor(cursor: &str) -> Result<u64, JournalError> {
    if cursor.is_empty() || cursor.len() > 20 || !cursor.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(JournalError::InvalidCursor(
            "audit cursor is not a valid sequence",
        ));
    }
    cursor.parse().map_err(|_| {
        JournalError::InvalidCursor("audit cursor exceeds the supported sequence range")
    })
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn json_value_within_audit_bounds(root: &Value) -> bool {
    let mut stack = vec![(root, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if depth > MAXIMUM_AUDIT_JSON_DEPTH || nodes > MAXIMUM_AUDIT_JSON_NODES {
            return false;
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            }
            Value::Object(map) => {
                stack.extend(map.values().map(|value| (value, depth.saturating_add(1))));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn reject_reserved_binding_fields(payload: &Value) -> Result<(), JournalError> {
    const RESERVED: [&str; 15] = [
        "snapshot_digest",
        "capability_digest",
        "capability_uses",
        "capability_revoked",
        "approval_nonce",
        "object_kind",
        "object_id",
        "object_digest",
        "stage_digest",
        "stage_status",
        "idempotency_adapter",
        "idempotency_key",
        "idempotency_status",
        "idempotency_updated_at",
        "receipt_digest",
    ];
    if payload
        .as_object()
        .is_some_and(|payload| payload.keys().any(|key| RESERVED.contains(&key.as_str())))
    {
        return Err(JournalError::Invariant(
            "generic audit event uses a reserved durable-state binding field".into(),
        ));
    }
    Ok(())
}

/// Defensively replace values under commonly sensitive field names.
pub fn redact_value(mut value: Value) -> Value {
    redact_in_place(&mut value);
    value
}

fn redact_in_place(value: &mut Value) {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if is_sensitive_field_name(key) {
                        *child = Value::String("[REDACTED]".into());
                    } else {
                        stack.push(child);
                    }
                }
            }
            Value::Array(values) => stack.extend(values),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn is_sensitive_field_name(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    let compact = normalized.replace('_', "");
    [
        "authorization",
        "bearer",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
        || ["apikey", "accesskey", "privatekey"]
            .iter()
            .any(|sensitive| compact.ends_with(sensitive))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn receipt_body_has_safe_shape(receipt: &Receipt) -> bool {
    if !valid_sha256_hex(&receipt.effect_digest)
        || !valid_sha256_hex(&receipt.result_digest)
        || receipt.outcome.is_empty()
        || receipt.outcome.len() > 128
        || !receipt
            .outcome
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
        || !json_value_within_audit_bounds(&receipt.result)
    {
        return false;
    }
    let mut body = receipt.clone();
    body.authentication.clear();
    serde_json::to_vec(&body).is_ok_and(|bytes| bytes.len() <= MAXIMUM_AUDIT_PAYLOAD_BYTES)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::mpsc, thread, time::Duration as StdDuration};

    use chrono::Duration;
    use serde_json::json;
    use veyra_protocol::{ExecutionId, IntentId, PROTOCOL_VERSION, PlanId, PrincipalId, ReceiptId};

    use super::*;

    fn journal() -> Journal {
        Journal::in_memory([7; 32]).unwrap()
    }

    fn transaction(state: TransactionState) -> Transaction {
        let now = Utc::now();
        Transaction {
            schema_version: PROTOCOL_VERSION.into(),
            id: TransactionId::new(),
            intent_id: IntentId::new(),
            plan_id: PlanId::new(),
            state,
            effect_ids: vec![],
            receipt_ids: vec![],
            revision: 0,
            created_at: now,
            updated_at: now,
            manual_recovery_reason: None,
        }
    }

    fn capability(max_uses: u32) -> Capability {
        let now = Utc::now();
        Capability {
            id: CapabilityId::new(),
            principal_id: PrincipalId::new(),
            intent_id: None,
            transaction_id: None,
            adapter: "filesystem".into(),
            operations: vec!["create".into()],
            resources: vec![veyra_protocol::ResourceScope::Filesystem {
                workspace: "demo".into(),
                path: "notes".into(),
            }],
            constraints: BTreeMap::new(),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::minutes(5),
            nonce: format!("nonce-{}", CapabilityId::new()),
            max_uses,
            issued_at: now,
        }
    }

    fn unsigned_receipt(transaction_id: TransactionId) -> Receipt {
        Receipt {
            id: ReceiptId::new(),
            execution_id: ExecutionId::new(),
            transaction_id,
            effect_id: veyra_protocol::EffectId::new(),
            effect_digest: "aa".repeat(32),
            outcome: "created".into(),
            result_digest: "bb".repeat(32),
            result: json!({"path": "notes/hello.txt"}),
            issued_at: Utc::now(),
            signer_key_id: String::new(),
            authentication: String::new(),
        }
    }

    #[test]
    fn chain_detects_payload_tampering_and_missing_links() {
        let journal = journal();
        let tx = transaction(TransactionState::Draft);
        journal.create_transaction(&tx).unwrap();
        journal
            .append_event(Some(tx.id), "test.event", None, json!({"safe": true}))
            .unwrap();
        assert!(journal.verify_chain().unwrap().valid);

        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE audit_events SET payload_json = '{\"safe\":false}' WHERE sequence = 1",
                    [],
                )
                .unwrap();
        }
        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_sequence, Some(1));
    }

    #[test]
    fn malformed_audit_envelopes_are_reported_as_failed_verification() {
        let journal = journal();
        journal
            .append_event(None, "first", None, json!({"safe": true}))
            .unwrap();
        journal
            .append_event(None, "second", None, json!({"safe": true}))
            .unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE audit_events SET recorded_at = 'not-a-timestamp' WHERE sequence = 2",
                    [],
                )
                .unwrap();
        }

        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.events_checked, 1);
        assert_eq!(verification.first_invalid_sequence, Some(2));
        assert_eq!(
            verification.message,
            "audit event has a malformed timestamp"
        );
    }

    #[test]
    fn local_head_anchor_detects_deleted_tail_events() {
        let journal = journal();
        journal
            .append_event(None, "first", None, json!({"safe": true}))
            .unwrap();
        journal
            .append_event(None, "second", None, json!({"safe": true}))
            .unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute("DELETE FROM audit_events WHERE sequence = 2", [])
                .unwrap();
        }
        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_sequence, Some(2));
        assert!(matches!(
            journal.append_event(None, "third", None, json!({})),
            Err(JournalError::Corrupt { .. })
        ));
    }

    #[test]
    fn immutable_object_digest_is_checked_when_loaded() {
        let journal = journal();
        let principal = veyra_protocol::Principal {
            id: PrincipalId::new(),
            display_name: "Original".into(),
            kind: veyra_protocol::PrincipalKind::Human,
        };
        journal
            .put_object("principal", &principal.id.to_string(), &principal)
            .unwrap();
        let mut tampered = principal.clone();
        tampered.display_name = "Tampered".into();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE objects SET canonical_json = ?1, digest = ?2 WHERE kind = 'principal' AND id = ?3",
                    params![
                        String::from_utf8(canonical_json(&tampered).unwrap()).unwrap(),
                        canonical_digest(&tampered).unwrap(),
                        principal.id.to_string()
                    ],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.get_object::<veyra_protocol::Principal>("principal", &principal.id.to_string()),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn malformed_snapshot_json_is_reported_as_failed_verification() {
        let journal = journal();
        let snapshot = transaction(TransactionState::Draft);
        journal.create_transaction(&snapshot).unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE transactions SET json = '{' WHERE id = ?1",
                    params![snapshot.id.to_string()],
                )
                .unwrap();
        }

        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_sequence, None);
        assert_eq!(
            verification.message,
            "transaction snapshots contain malformed JSON"
        );
    }

    #[test]
    fn grouped_reads_hold_one_snapshot_across_concurrent_updates() {
        let journal = journal();
        let original = transaction(TransactionState::Draft);
        journal.create_transaction(&original).unwrap();

        let mut updated = original.clone();
        updated.state = TransactionState::Planned;
        updated.revision = 1;
        updated.updated_at = Utc::now();

        let writer = journal.clone();
        let (start_sender, start_receiver) = mpsc::channel();
        let (attempt_sender, attempt_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let writer_thread = thread::spawn(move || {
            start_receiver.recv().unwrap();
            attempt_sender.send(()).unwrap();
            done_sender
                .send(writer.update_transaction(
                    &updated,
                    "transaction.planned",
                    None,
                    json!({"state": "planned"}),
                ))
                .unwrap();
        });

        journal
            .read_snapshot(|snapshot| {
                let before = snapshot.transaction(original.id)?;
                start_sender.send(()).unwrap();
                attempt_receiver.recv().unwrap();
                assert!(
                    done_receiver
                        .recv_timeout(StdDuration::from_millis(100))
                        .is_err(),
                    "a concurrent writer must not complete inside a grouped read"
                );
                let after = snapshot.transaction(original.id)?;
                assert_eq!(before, after);
                assert_eq!(after.state, TransactionState::Draft);
                Ok(())
            })
            .unwrap();

        done_receiver
            .recv_timeout(StdDuration::from_secs(2))
            .unwrap()
            .unwrap();
        writer_thread.join().unwrap();
        assert_eq!(
            journal.transaction(original.id).unwrap().state,
            TransactionState::Planned
        );
    }

    #[test]
    fn deleted_immutable_object_cannot_be_silently_recreated() {
        let journal = journal();
        let principal = veyra_protocol::Principal {
            id: PrincipalId::new(),
            display_name: "Bound".into(),
            kind: veyra_protocol::PrincipalKind::Human,
        };
        journal
            .put_object("principal", &principal.id.to_string(), &principal)
            .unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM objects WHERE kind = 'principal' AND id = ?1",
                    params![principal.id.to_string()],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.get_object::<veyra_protocol::Principal>("principal", &principal.id.to_string()),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(matches!(
            journal.put_object("principal", &principal.id.to_string(), &principal),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn legacy_immutable_object_is_anchored_once() {
        let journal = journal();
        let principal = veyra_protocol::Principal {
            id: PrincipalId::new(),
            display_name: "Legacy".into(),
            kind: veyra_protocol::PrincipalKind::Human,
        };
        let serialized = String::from_utf8(canonical_json(&principal).unwrap()).unwrap();
        let digest = canonical_digest(&principal).unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM metadata WHERE key = ?1",
                    params![OBJECT_BINDING_KEY],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO objects(kind, id, canonical_json, digest, created_at) VALUES ('principal', ?1, ?2, ?3, ?4)",
                    params![principal.id.to_string(), serialized, digest, Utc::now().to_rfc3339()],
                )
                .unwrap();
        }
        journal.anchor_unbound_objects().unwrap();
        journal.anchor_unbound_objects().unwrap();
        assert_eq!(journal.export_events(None).unwrap().len(), 1);
        assert_eq!(
            journal.export_events(None).unwrap()[0].event_type,
            "object.snapshot_anchored"
        );
        assert_eq!(
            journal
                .get_object::<veyra_protocol::Principal>("principal", &principal.id.to_string())
                .unwrap(),
            principal
        );
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn staged_effect_content_is_bound_to_the_audit_chain() {
        let journal = journal();
        let transaction_id = TransactionId::new();
        let effect_id = veyra_protocol::EffectId::new();
        journal
            .store_stage(
                transaction_id,
                effect_id,
                "filesystem",
                &json!({"captured": "original"}),
            )
            .unwrap();
        assert_eq!(
            journal.stage::<Value>(transaction_id, effect_id).unwrap(),
            json!({"captured": "original"})
        );
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE staged_effects SET stage_json = '{\"captured\":\"tampered\"}', adapter = 'process' WHERE transaction_id = ?1 AND effect_id = ?2",
                    params![transaction_id.to_string(), effect_id.to_string()],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.stage::<Value>(transaction_id, effect_id),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn legacy_stage_is_anchored_once() {
        let journal = journal();
        let transaction_id = TransactionId::new();
        let effect_id = veyra_protocol::EffectId::new();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM metadata WHERE key = ?1",
                    params![STAGE_BINDING_KEY],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO staged_effects(transaction_id, effect_id, adapter, stage_json, status) VALUES (?1, ?2, 'filesystem', ?3, 'staged')",
                    params![
                        transaction_id.to_string(),
                        effect_id.to_string(),
                        "{\"captured\":\"legacy\"}"
                    ],
                )
                .unwrap();
        }
        journal.anchor_unbound_stages().unwrap();
        journal.anchor_unbound_stages().unwrap();
        assert_eq!(journal.export_events(None).unwrap().len(), 1);
        assert_eq!(
            journal.export_events(None).unwrap()[0].event_type,
            "stage.snapshot_anchored"
        );
        assert_eq!(
            journal.stage::<Value>(transaction_id, effect_id).unwrap(),
            json!({"captured": "legacy"})
        );
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn transaction_snapshot_must_match_its_indexed_state() {
        let journal = journal();
        let snapshot = transaction(TransactionState::Draft);
        journal.create_transaction(&snapshot).unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE transactions SET state = 'committed' WHERE id = ?1",
                    params![snapshot.id.to_string()],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.transaction(snapshot.id),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(matches!(
            journal.transactions(),
            Err(JournalError::Corrupt { .. })
        ));
    }

    #[test]
    fn transaction_snapshot_is_bound_to_the_audit_chain() {
        let journal = journal();
        let snapshot = transaction(TransactionState::Draft);
        journal.create_transaction(&snapshot).unwrap();
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE transactions SET json = json_set(json, '$.plan_id', ?1) WHERE id = ?2",
                    params![PlanId::new().to_string(), snapshot.id.to_string()],
                )
                .unwrap();
        }

        assert!(matches!(
            journal.transaction(snapshot.id),
            Err(JournalError::Corrupt { .. })
        ));
        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert!(verification.message.contains("audit-bound digest"));
    }

    #[test]
    fn capability_content_and_mutable_facts_are_bound_to_the_audit_chain() {
        let journal = journal();
        let capability = capability(2);
        journal
            .store_capability(&capability, PrincipalId::new())
            .unwrap();
        assert!(journal.verify_chain().unwrap().valid);

        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE capabilities SET json = json_set(json, '$.max_uses', 99) WHERE id = ?1",
                    params![capability.id.to_string()],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.capabilities(),
            Err(JournalError::Corrupt { .. })
        ));
        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert!(verification.message.contains("audit-bound state"));

        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE capabilities SET json = ?1, uses = 1 WHERE id = ?2",
                    params![
                        serde_json::to_string(&capability).unwrap(),
                        capability.id.to_string()
                    ],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.capabilities(),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn deleted_transaction_and_capability_snapshots_are_detected_from_audit_evidence() {
        let transaction_journal = journal();
        let snapshot = transaction(TransactionState::Draft);
        transaction_journal.create_transaction(&snapshot).unwrap();
        {
            let connection = transaction_journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM transactions WHERE id = ?1",
                    params![snapshot.id.to_string()],
                )
                .unwrap();
        }
        assert!(!transaction_journal.verify_chain().unwrap().valid);

        let capability_journal = journal();
        let capability = capability(1);
        capability_journal
            .store_capability(&capability, PrincipalId::new())
            .unwrap();
        {
            let connection = capability_journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM capabilities WHERE id = ?1",
                    params![capability.id.to_string()],
                )
                .unwrap();
        }
        assert!(!capability_journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn generic_events_cannot_shadow_reserved_state_bindings() {
        let journal = journal();
        let snapshot = transaction(TransactionState::Draft);
        journal.create_transaction(&snapshot).unwrap();
        let event_count = journal.export_events(None).unwrap().len();

        assert!(matches!(
            journal.append_event(
                Some(snapshot.id),
                "test.shadow",
                None,
                json!({"snapshot_digest": "00".repeat(32)}),
            ),
            Err(JournalError::Invariant(_))
        ));
        assert!(matches!(
            journal.append_event(
                None,
                "test.shadow",
                None,
                json!({
                    "capability_id": CapabilityId::new(),
                    "capability_uses": 0,
                    "capability_revoked": false,
                }),
            ),
            Err(JournalError::Invariant(_))
        ));
        assert_eq!(journal.export_events(None).unwrap().len(), event_count);
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn capability_consumption_and_revocation_update_audit_bound_facts() {
        let journal = journal();
        let issuer = PrincipalId::new();
        let revoker = PrincipalId::new();
        let capability = capability(2);
        journal.store_capability(&capability, issuer).unwrap();

        journal.consume_capabilities(&[capability.id]).unwrap();
        let (_, facts) = journal.capabilities().unwrap().pop().unwrap();
        assert_eq!(facts.uses, 1);
        assert!(!facts.revoked);
        journal.revoke_capability(capability.id, revoker).unwrap();
        let (_, facts) = journal.capabilities().unwrap().pop().unwrap();
        assert_eq!(facts.uses, 1);
        assert!(facts.revoked);
        assert!(journal.verify_chain().unwrap().valid);

        let events = journal.export_events(None).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec![
                "capability.issued",
                "capability.consumed",
                "capability.revoked"
            ]
        );
        let event_count = events.len();
        assert!(matches!(
            journal.consume_capabilities(&[capability.id]),
            Err(JournalError::CapabilityUnavailable(id)) if id == capability.id
        ));
        assert!(matches!(
            journal.revoke_capability(capability.id, revoker),
            Err(JournalError::CapabilityUnavailable(id)) if id == capability.id
        ));
        assert_eq!(journal.export_events(None).unwrap().len(), event_count);
    }

    #[test]
    fn legacy_capability_snapshot_is_anchored_once() {
        let journal = journal();
        let capability = capability(3);
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM metadata WHERE key = ?1",
                    params![CAPABILITY_BINDING_KEY],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO capabilities(id, nonce, json, uses, revoked) VALUES (?1, ?2, ?3, 2, 1)",
                    params![
                        capability.id.to_string(),
                        capability.nonce,
                        serde_json::to_string(&capability).unwrap()
                    ],
                )
                .unwrap();
        }
        journal.anchor_unbound_capability_snapshots().unwrap();
        journal.anchor_unbound_capability_snapshots().unwrap();

        let events = journal.export_events(None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "capability.snapshot_anchored");
        let (_, facts) = journal.capabilities().unwrap().pop().unwrap();
        assert_eq!(facts.uses, 2);
        assert!(facts.revoked);
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn keyset_pages_are_bounded_stable_and_resumable() {
        let journal = journal();
        let mut snapshots = Vec::new();
        for offset in 0..3 {
            let mut snapshot = transaction(TransactionState::Draft);
            snapshot.updated_at += Duration::seconds(offset);
            journal.create_transaction(&snapshot).unwrap();
            snapshots.push(snapshot);
        }

        let first = journal.transaction_page(2, None).unwrap();
        assert_eq!(
            first.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![snapshots[2].id, snapshots[1].id]
        );
        let second = journal
            .transaction_page(2, first.next_cursor.as_deref())
            .unwrap();
        assert_eq!(second.items[0].id, snapshots[0].id);
        assert!(second.next_cursor.is_none());

        let audit_first = journal.audit_event_page(None, 2, None).unwrap();
        assert_eq!(audit_first.items.len(), 2);
        let audit_second = journal
            .audit_event_page(None, 2, audit_first.next_cursor.as_deref())
            .unwrap();
        assert_eq!(audit_second.items.len(), 1);
        assert!(audit_second.next_cursor.is_none());
        let recent_first = journal.recent_audit_event_page(None, 2, None).unwrap();
        assert_eq!(
            recent_first
                .items
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        let recent_second = journal
            .recent_audit_event_page(None, 2, recent_first.next_cursor.as_deref())
            .unwrap();
        assert_eq!(recent_second.items[0].sequence, 1);
        assert!(recent_second.next_cursor.is_none());
        assert!(matches!(
            journal.transaction_page(2, Some("not-a-cursor")),
            Err(JournalError::InvalidCursor(_))
        ));
        assert!(matches!(
            journal.audit_event_page(None, 0, None),
            Err(JournalError::InvalidCursor(_))
        ));
    }

    #[test]
    fn indexed_object_queries_do_not_scan_unrelated_bindings_into_memory() {
        let journal = journal();
        let transaction_id = TransactionId::new();
        let other_transaction_id = TransactionId::new();
        let effect_id = veyra_protocol::EffectId::new();
        journal
            .put_object(
                "test_binding",
                "matching",
                &json!({"transaction_id": transaction_id, "effect_id": effect_id}),
            )
            .unwrap();
        journal
            .put_object(
                "test_binding",
                "unrelated",
                &json!({"transaction_id": other_transaction_id, "effect_id": veyra_protocol::EffectId::new()}),
            )
            .unwrap();

        assert_eq!(
            journal
                .objects_for_transaction::<Value>("test_binding", transaction_id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            journal
                .objects_for_effects::<Value>("test_binding", &[effect_id])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn audit_payloads_redact_nested_secrets() {
        let journal = journal();
        journal
            .append_event(
                None,
                "redaction.test",
                None,
                json!({
                    "authorization": "Bearer raw-secret",
                    "nested": {
                        "service_token": "raw-secret",
                        "clientSecret": "raw-secret",
                        "service.accessKey": "raw-secret",
                        "safe": "visible"
                    }
                }),
            )
            .unwrap();
        let serialized = serde_json::to_string(&journal.export_events(None).unwrap()).unwrap();
        assert!(!serialized.contains("raw-secret"));
        assert!(serialized.contains("visible"));
        assert!(serialized.contains("[REDACTED]"));
    }

    #[test]
    fn forged_or_modified_receipts_are_rejected() {
        let journal = journal();
        let mut receipt = journal
            .sign_receipt(unsigned_receipt(TransactionId::new()))
            .unwrap();
        journal.verify_receipt(&receipt).unwrap();
        receipt.outcome = "spoofed".into();
        assert!(matches!(
            journal.verify_receipt(&receipt),
            Err(JournalError::ForgedReceipt)
        ));

        let mut malformed = unsigned_receipt(TransactionId::new());
        malformed.effect_digest = "AA".repeat(32);
        assert!(matches!(
            journal.sign_receipt(malformed),
            Err(JournalError::Invariant(_))
        ));
    }

    #[test]
    fn idempotency_completion_rejects_a_receipt_for_another_effect() {
        let journal = journal();
        let reserved_digest = "cc".repeat(32);
        journal
            .reserve_execution("filesystem", "bound-key", &reserved_digest)
            .unwrap();
        let receipt = journal
            .sign_receipt(unsigned_receipt(TransactionId::new()))
            .unwrap();
        assert!(matches!(
            journal.complete_execution("filesystem", "bound-key", &reserved_digest, &receipt,),
            Err(JournalError::Invariant(_))
        ));
        assert_eq!(
            journal
                .reserve_execution("filesystem", "bound-key", &reserved_digest)
                .unwrap(),
            IdempotencyReservation::InProgress
        );
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn duplicate_idempotency_returns_original_receipt() {
        let journal = journal();
        let tx_id = TransactionId::new();
        let effect_digest = "aa".repeat(32);
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", &effect_digest)
                .unwrap(),
            IdempotencyReservation::Acquired
        );
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", &effect_digest)
                .unwrap(),
            IdempotencyReservation::InProgress
        );
        let receipt = journal.sign_receipt(unsigned_receipt(tx_id)).unwrap();
        journal
            .complete_execution("filesystem", "key", &effect_digest, &receipt)
            .unwrap();
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", &effect_digest)
                .unwrap(),
            IdempotencyReservation::Completed(Box::new(receipt))
        );
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", &"dd".repeat(32))
                .unwrap(),
            IdempotencyReservation::Conflict
        );
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn idempotency_state_is_audit_bound_and_deletion_is_detected() {
        let tampered = journal();
        let digest = "bb".repeat(32);
        tampered
            .reserve_execution("filesystem", "tamper-key", &digest)
            .unwrap();
        {
            let connection = tampered.lock().unwrap();
            connection
                .execute(
                    "UPDATE idempotency SET status = 'unknown', updated_at = ?1 WHERE adapter = 'filesystem' AND key = 'tamper-key'",
                    params![Utc::now().to_rfc3339()],
                )
                .unwrap();
        }
        assert!(matches!(
            tampered.reserve_execution("filesystem", "tamper-key", &digest),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!tampered.verify_chain().unwrap().valid);

        let deleted = journal();
        deleted
            .reserve_execution("filesystem", "deleted-key", &digest)
            .unwrap();
        {
            let connection = deleted.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM idempotency WHERE adapter = 'filesystem' AND key = 'deleted-key'",
                    [],
                )
                .unwrap();
        }
        assert!(matches!(
            deleted.reserve_execution("filesystem", "deleted-key", &digest),
            Err(JournalError::Corrupt { .. })
        ));
        assert!(!deleted.verify_chain().unwrap().valid);
    }

    #[test]
    fn unknown_and_legacy_idempotency_states_remain_fail_closed() {
        let active = journal();
        let digest = "cc".repeat(32);
        active
            .reserve_execution("filesystem", "unknown-key", &digest)
            .unwrap();
        active
            .mark_execution_unknown("filesystem", "unknown-key", &digest)
            .unwrap();
        assert_eq!(
            active
                .reserve_execution("filesystem", "unknown-key", &digest)
                .unwrap(),
            IdempotencyReservation::Unknown
        );
        assert!(active.verify_chain().unwrap().valid);

        let legacy = journal();
        let updated_at = Utc::now().to_rfc3339();
        {
            let connection = legacy.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM metadata WHERE key = ?1",
                    params![IDEMPOTENCY_BINDING_KEY],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO idempotency(adapter, key, effect_digest, status, receipt_json, updated_at) VALUES ('filesystem', 'legacy-key', ?1, 'unknown', NULL, ?2)",
                    params![digest, updated_at],
                )
                .unwrap();
        }
        legacy.anchor_unbound_idempotency().unwrap();
        legacy.anchor_unbound_idempotency().unwrap();
        assert_eq!(legacy.export_events(None).unwrap().len(), 1);
        assert_eq!(
            legacy.export_events(None).unwrap()[0].event_type,
            "idempotency.snapshot_anchored"
        );
        assert_eq!(
            legacy
                .reserve_execution("filesystem", "legacy-key", &digest)
                .unwrap(),
            IdempotencyReservation::Unknown
        );
        assert!(legacy.verify_chain().unwrap().valid);
    }

    #[test]
    fn approval_nonce_is_single_use() {
        let journal = journal();
        let now = Utc::now();
        let grant = ApprovalGrant {
            id: veyra_protocol::ApprovalGrantId::new(),
            request_id: veyra_protocol::ApprovalRequestId::new(),
            transaction_id: TransactionId::new(),
            approver_id: PrincipalId::new(),
            effect_digest: "digest".into(),
            nonce: "once".into(),
            granted_at: now,
            expires_at: now + Duration::minutes(1),
        };
        journal.consume_approval(&grant).unwrap();
        assert!(matches!(
            journal.consume_approval(&grant),
            Err(JournalError::ApprovalReplay)
        ));
        assert!(journal.approval_nonce_consumed(&grant.nonce).unwrap());
        assert!(journal.verify_chain().unwrap().valid);
    }

    #[test]
    fn replay_rolls_back_capability_consumption_and_nonce_rows_are_audit_bound() {
        let journal = journal();
        let capability = capability(2);
        journal
            .store_capability(&capability, PrincipalId::new())
            .unwrap();
        let now = Utc::now();
        let grant = ApprovalGrant {
            id: ApprovalGrantId::new(),
            request_id: veyra_protocol::ApprovalRequestId::new(),
            transaction_id: TransactionId::new(),
            approver_id: PrincipalId::new(),
            effect_digest: "digest".into(),
            nonce: "atomic-once".into(),
            granted_at: now,
            expires_at: now + Duration::minutes(1),
        };
        journal.consume_approval(&grant).unwrap();
        let event_count = journal.export_events(None).unwrap().len();

        assert!(matches!(
            journal.consume_authority(&[capability.id], Some(&grant)),
            Err(JournalError::ApprovalReplay)
        ));
        let (_, facts) = journal.capabilities().unwrap().pop().unwrap();
        assert_eq!(facts.uses, 0);
        assert_eq!(journal.export_events(None).unwrap().len(), event_count);

        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "DELETE FROM consumed_approval_nonces WHERE nonce = ?1",
                    params![grant.nonce],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.approval_nonce_consumed(&grant.nonce),
            Err(JournalError::Corrupt { .. })
        ));
        let verification = journal.verify_chain().unwrap();
        assert!(!verification.valid);
        assert!(verification.message.contains("approval consumption"));
    }

    #[test]
    fn optimistic_snapshot_update_is_atomic_with_event() {
        let journal = journal();
        let mut tx = transaction(TransactionState::Draft);
        journal.create_transaction(&tx).unwrap();
        tx.state = TransactionState::Planned;
        tx.revision = 1;
        tx.updated_at = Utc::now();
        journal
            .update_transaction(&tx, "transaction.planned", None, json!({}))
            .unwrap();
        let events_before = journal.export_events(None).unwrap().len();

        tx.state = TransactionState::Preflighted;
        tx.revision = 3;
        assert!(matches!(
            journal.update_transaction(&tx, "transaction.preflighted", None, json!({})),
            Err(JournalError::RevisionConflict { .. })
        ));
        assert_eq!(journal.export_events(None).unwrap().len(), events_before);
        assert_eq!(journal.transaction(tx.id).unwrap().revision, 1);
    }

    #[test]
    fn restart_classification_is_conservative_at_every_recoverable_phase() {
        let journal = journal();
        let cases = [
            (TransactionState::Draft, RecoveryAction::ResumeSafe),
            (TransactionState::Planned, RecoveryAction::ResumeSafe),
            (TransactionState::Preflighted, RecoveryAction::ResumeSafe),
            (
                TransactionState::AwaitingApproval,
                RecoveryAction::ResumeSafe,
            ),
            (TransactionState::Approved, RecoveryAction::ResumeSafe),
            (TransactionState::Staged, RecoveryAction::ManualRecovery),
            (TransactionState::Executing, RecoveryAction::ManualRecovery),
            (TransactionState::Verifying, RecoveryAction::ManualRecovery),
            (
                TransactionState::Compensating,
                RecoveryAction::ManualRecovery,
            ),
            (
                TransactionState::ManualRecovery,
                RecoveryAction::ManualRecovery,
            ),
        ];
        let mut expected = std::collections::HashMap::new();
        for (state, action) in cases {
            let snapshot = transaction(state);
            expected.insert(snapshot.id, (state, action));
            journal.create_transaction(&snapshot).unwrap();
        }
        let records = journal.recovery_actions().unwrap();
        assert_eq!(records.len(), expected.len());
        for record in records {
            assert_eq!(
                (record.state, record.action),
                expected[&record.transaction_id]
            );
        }
        let mut paged = Vec::new();
        let mut cursor = None;
        loop {
            let page = journal.recovery_action_page(3, cursor.as_deref()).unwrap();
            paged.extend(page.items);
            let Some(next) = page.next_cursor else {
                break;
            };
            cursor = Some(next);
        }
        assert_eq!(paged.len(), expected.len());
        assert_eq!(
            paged
                .iter()
                .map(|record| record.transaction_id)
                .collect::<HashSet<_>>()
                .len(),
            expected.len()
        );
    }

    #[test]
    fn concurrent_idempotency_reservation_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let journal = journal();
        let barrier = Arc::new(Barrier::new(12));
        let handles = (0..12)
            .map(|_| {
                let journal = journal.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    journal
                        .reserve_execution("filesystem", "concurrent-key", &"dd".repeat(32))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let reservations = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reservations
                .iter()
                .filter(|item| matches!(item, IdempotencyReservation::Acquired))
                .count(),
            1
        );
        assert_eq!(
            reservations
                .iter()
                .filter(|item| matches!(item, IdempotencyReservation::InProgress))
                .count(),
            11
        );
    }

    #[test]
    fn durable_reopen_preserves_chain_and_marks_in_flight_execution_manual() {
        let temporary = tempfile::TempDir::new().unwrap();
        let database = temporary.path().join("journal.sqlite3");
        let key = temporary.path().join("receipt.key");
        let snapshot = transaction(TransactionState::Executing);
        {
            let journal = Journal::open(&database, &key).unwrap();
            journal.create_transaction(&snapshot).unwrap();
            journal
                .append_event(
                    Some(snapshot.id),
                    "failure_injection.process_exit",
                    None,
                    json!({"phase": "executing"}),
                )
                .unwrap();
        }
        let reopened = Journal::open(&database, &key).unwrap();
        assert!(reopened.verify_chain().unwrap().valid);
        assert_eq!(
            reopened.recovery_actions().unwrap(),
            vec![RecoveryRecord {
                transaction_id: snapshot.id,
                state: TransactionState::Executing,
                action: RecoveryAction::ManualRecovery,
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_receipt_key_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::TempDir::new().unwrap();
        let database = temporary.path().join("journal.sqlite3");
        let key = temporary.path().join("receipt.key");
        fs::write(&key, [7_u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Journal::open(database, key),
            Err(JournalError::Invariant(_))
        ));
    }
}
