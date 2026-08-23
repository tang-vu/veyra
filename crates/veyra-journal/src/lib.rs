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
    Connection, OptionalExtension, Transaction as SqlTransaction, TransactionBehavior, params,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use veyra_protocol::{
    ApprovalGrant, ApprovalRequest, AuditEvent, AuditEventId, AuditVerification, Capability,
    CapabilityId, Receipt, Transaction, TransactionId, TransactionState, canonical_digest,
    canonical_json,
};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DATABASE_SCHEMA_VERSION: &str = "1";
const AUDIT_COUNT_KEY: &str = "audit_event_count";
const AUDIT_HEAD_KEY: &str = "audit_head_hash";
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
CREATE TABLE IF NOT EXISTS objects (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(kind, id)
) STRICT;
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    state TEXT NOT NULL,
    json TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    json TEXT NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
) STRICT;
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
        let bytes = canonical_json(value).map_err(JournalError::Canonical)?;
        let serialized = String::from_utf8(bytes).map_err(|_| {
            JournalError::Invariant("canonical JSON was not valid UTF-8".to_owned())
        })?;
        let digest = canonical_digest(value).map_err(JournalError::Canonical)?;
        let connection = self.lock()?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT digest FROM objects WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?;
        if let Some(existing) = existing {
            if existing == digest {
                return Ok(digest);
            }
            return Err(JournalError::ObjectConflict {
                kind: kind.to_owned(),
                id: id.to_owned(),
            });
        }
        connection
            .execute(
                "INSERT INTO objects(kind, id, canonical_json, digest, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![kind, id, serialized, digest, Utc::now().to_rfc3339()],
            )
            .map_err(JournalError::Database)?;
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
        let (serialized, digest): (String, String) = connection
            .query_row(
                "SELECT canonical_json, digest FROM objects WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(JournalError::Database)?
            .ok_or_else(|| JournalError::NotFound {
                kind: kind.to_owned(),
                id: id.to_owned(),
            })?;
        deserialize_verified_object(kind, id, &serialized, &digest)
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
            .map_err(JournalError::Database)?;
        rows.map(|row| {
            let (id, serialized, digest) = row.map_err(JournalError::Database)?;
            deserialize_verified_object(kind, &id, &serialized, &digest)
        })
        .collect()
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
            json!({"state": transaction.state, "revision": transaction.revision}),
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
            payload,
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

    /// List transaction snapshots newest first.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error.
    pub fn transactions(&self) -> Result<Vec<Transaction>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT id, revision, state, json FROM transactions ORDER BY updated_at DESC")
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(JournalError::Database)?;
        rows.map(|row| {
            let (id, revision, state, serialized) = row.map_err(JournalError::Database)?;
            deserialize_transaction_snapshot(&id, revision, &state, &serialized)
        })
        .collect()
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
        let events = read_events(&connection, None)?;
        let (expected_count, expected_head) = audit_anchor(&connection)?;
        Ok(verify_events(&events, expected_count, &expected_head))
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

    /// Persist an issued capability with a zero use count.
    ///
    /// # Errors
    ///
    /// Returns a database or serialization error, or an object conflict for a reused ID.
    pub fn store_capability(&self, capability: &Capability) -> Result<(), JournalError> {
        let serialized = serde_json::to_string(capability).map_err(JournalError::Serialization)?;
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO capabilities(id, nonce, json, uses, revoked) VALUES (?1, ?2, ?3, 0, 0)",
                params![capability.id.to_string(), capability.nonce, serialized],
            )
            .map_err(JournalError::Database)?;
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
            .prepare("SELECT json, uses, revoked FROM capabilities")
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })
            .map_err(JournalError::Database)?;
        rows.map(|row| {
            let (serialized, uses, revoked) = row.map_err(JournalError::Database)?;
            Ok((
                serde_json::from_str(&serialized).map_err(JournalError::Serialization)?,
                CapabilityFacts {
                    uses: u32::try_from(uses).map_err(|_| {
                        JournalError::Invariant("negative or excessive capability use count".into())
                    })?,
                    revoked,
                },
            ))
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
            let row: Option<(String, i64, bool)> = sql
                .query_row(
                    "SELECT json, uses, revoked FROM capabilities WHERE id = ?1",
                    params![id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(JournalError::Database)?;
            let Some((serialized, uses, revoked)) = row else {
                return Err(JournalError::CapabilityUnavailable(*id));
            };
            let capability: Capability =
                serde_json::from_str(&serialized).map_err(JournalError::Serialization)?;
            if revoked
                || uses < 0
                || u32::try_from(uses).map_or(true, |count| count >= capability.max_uses)
            {
                return Err(JournalError::CapabilityUnavailable(*id));
            }
            sql.execute(
                "UPDATE capabilities SET uses = uses + 1 WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(JournalError::Database)?;
        }
        sql.commit().map_err(JournalError::Database)?;
        Ok(())
    }

    /// Revoke a capability so future policy checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::CapabilityUnavailable`] if the ID is unknown, or a database error.
    pub fn revoke_capability(&self, id: CapabilityId) -> Result<(), JournalError> {
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE capabilities SET revoked = 1 WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(JournalError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(JournalError::CapabilityUnavailable(id))
        }
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
        let connection = self.lock()?;
        match connection.execute(
            "INSERT INTO consumed_approval_nonces(nonce, grant_id, consumed_at) VALUES (?1, ?2, ?3)",
            params![grant.nonce, grant.id.to_string(), Utc::now().to_rfc3339()],
        ) {
            Ok(1) => Ok(()),
            Ok(_) => Err(JournalError::Invariant(
                "approval consumption changed an unexpected number of rows".into(),
            )),
            Err(error) if is_constraint_violation(&error) => Err(JournalError::ApprovalReplay),
            Err(error) => Err(JournalError::Database(error)),
        }
    }

    /// Return all approval nonces that have already authorized execution.
    ///
    /// # Errors
    ///
    /// Returns a database error.
    pub fn consumed_approval_nonces(&self) -> Result<HashSet<String>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT nonce FROM consumed_approval_nonces")
            .map_err(JournalError::Database)?;
        let rows = statement
            .query_map([], |row| row.get(0))
            .map_err(JournalError::Database)?;
        rows.map(|row| row.map_err(JournalError::Database))
            .collect()
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
        let mut connection = self.lock()?;
        let sql = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(JournalError::Database)?;
        let existing: Option<(String, String, Option<String>)> = sql
            .query_row(
                "SELECT effect_digest, status, receipt_json FROM idempotency WHERE adapter = ?1 AND key = ?2",
                params![adapter, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(JournalError::Database)?;
        let result = match existing {
            None => {
                sql.execute(
                    "INSERT INTO idempotency(adapter, key, effect_digest, status, receipt_json, updated_at) VALUES (?1, ?2, ?3, 'reserved', NULL, ?4)",
                    params![adapter, key, effect_digest, Utc::now().to_rfc3339()],
                )
                .map_err(JournalError::Database)?;
                IdempotencyReservation::Acquired
            }
            Some((stored_digest, _, _)) if stored_digest != effect_digest => {
                IdempotencyReservation::Conflict
            }
            Some((_, status, Some(serialized))) if status == "complete" => {
                let receipt =
                    serde_json::from_str(&serialized).map_err(JournalError::Serialization)?;
                IdempotencyReservation::Completed(Box::new(receipt))
            }
            Some((_, status, _)) if status == "unknown" => IdempotencyReservation::Unknown,
            Some(_) => IdempotencyReservation::InProgress,
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
        self.verify_receipt(receipt)?;
        let serialized = serde_json::to_string(receipt).map_err(JournalError::Serialization)?;
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE idempotency SET status = 'complete', receipt_json = ?1, updated_at = ?2 WHERE adapter = ?3 AND key = ?4 AND effect_digest = ?5 AND status = 'reserved'",
                params![serialized, Utc::now().to_rfc3339(), adapter, key, effect_digest],
            )
            .map_err(JournalError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(JournalError::Invariant(
                "idempotency reservation was not exclusively held".into(),
            ))
        }
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
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE idempotency SET status = 'unknown', updated_at = ?1 WHERE adapter = ?2 AND key = ?3 AND effect_digest = ?4 AND status = 'reserved'",
                params![Utc::now().to_rfc3339(), adapter, key, effect_digest],
            )
            .map_err(JournalError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(JournalError::Invariant(
                "could not mark idempotency reservation unknown".into(),
            ))
        }
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
        let connection = self.lock()?;
        match connection.execute(
            "INSERT INTO staged_effects(transaction_id, effect_id, adapter, stage_json, status) VALUES (?1, ?2, ?3, ?4, 'staged')",
            params![transaction_id.to_string(), effect_id.to_string(), adapter, serialized],
        ) {
            Ok(1) => Ok(()),
            Ok(_) => Err(JournalError::Invariant("stage insert changed no row".into())),
            Err(error) if is_constraint_violation(&error) => {
                Err(JournalError::Invariant("effect was already staged".into()))
            }
            Err(error) => Err(JournalError::Database(error)),
        }
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
        let serialized: String = connection
            .query_row(
                "SELECT stage_json FROM staged_effects WHERE transaction_id = ?1 AND effect_id = ?2",
                params![transaction_id.to_string(), effect_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(JournalError::Database)?
            .ok_or_else(|| JournalError::NotFound {
                kind: "stage".into(),
                id: effect_id.to_string(),
            })?;
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
        if receipt.signer_key_id != self.receipt_key_id.as_ref() {
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
        self.transactions()?
            .into_iter()
            .filter(|transaction| {
                !transaction.state.is_terminal()
                    || transaction.state == TransactionState::ManualRecovery
            })
            .map(|transaction| {
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
                            "terminal transaction passed recovery filter".into(),
                        ));
                    }
                };
                Ok(RecoveryRecord {
                    transaction_id: transaction.id,
                    state: transaction.state,
                    action,
                })
            })
            .collect()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, JournalError> {
        self.connection.lock().map_err(|_| JournalError::Poisoned)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// No external effect may be in flight; forward processing may resume.
    ResumeSafe,
    /// Automatic execution could duplicate or worsen an ambiguous effect.
    ManualRecovery,
}

/// One transaction discovered during restart recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
    let payload = redact_value(payload);
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
        let id: String = row.get(0).map_err(JournalError::Database)?;
        let tx_id: Option<String> = row.get(1).map_err(JournalError::Database)?;
        let sequence: i64 = row.get(2).map_err(JournalError::Database)?;
        let recorded_at: String = row.get(8).map_err(JournalError::Database)?;
        events.push(AuditEvent {
            id: id
                .parse()
                .map_err(|_| JournalError::Invariant("invalid audit event ID".into()))?,
            transaction_id: tx_id
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| JournalError::Invariant("invalid audit transaction ID".into()))?,
            sequence: u64::try_from(sequence)
                .map_err(|_| JournalError::Invariant("negative audit sequence".into()))?,
            event_type: row.get(3).map_err(JournalError::Database)?,
            causal_parent: row.get(4).map_err(JournalError::Database)?,
            payload: serde_json::from_str(
                &row.get::<_, String>(5).map_err(JournalError::Database)?,
            )
            .map_err(JournalError::Serialization)?,
            previous_hash: row.get(6).map_err(JournalError::Database)?,
            hash: row.get(7).map_err(JournalError::Database)?,
            recorded_at: DateTime::parse_from_rfc3339(&recorded_at)
                .map_err(|_| JournalError::Invariant("invalid audit timestamp".into()))?
                .with_timezone(&Utc),
        });
    }
    Ok(events)
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

fn verify_events(
    events: &[AuditEvent],
    expected_count: u64,
    expected_head: &str,
) -> AuditVerification {
    let mut previous = GENESIS_HASH.to_owned();
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        if event.sequence != expected_sequence || event.previous_hash != previous {
            return AuditVerification {
                valid: false,
                events_checked: u64::try_from(index).unwrap_or(u64::MAX),
                first_invalid_sequence: Some(event.sequence),
                message: "missing sequence or previous-hash link".into(),
            };
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
            return AuditVerification {
                valid: false,
                events_checked: u64::try_from(index).unwrap_or(u64::MAX),
                first_invalid_sequence: Some(event.sequence),
                message: "event content digest mismatch".into(),
            };
        }
        previous.clone_from(&event.hash);
    }
    let observed_count = u64::try_from(events.len()).unwrap_or(u64::MAX);
    if observed_count != expected_count || previous != expected_head {
        return AuditVerification {
            valid: false,
            events_checked: observed_count,
            first_invalid_sequence: observed_count.checked_add(1),
            message: "journal tail disagrees with its local count/hash anchor".into(),
        };
    }
    AuditVerification {
        valid: true,
        events_checked: observed_count,
        first_invalid_sequence: None,
        message: "journal hash chain is valid".into(),
    }
}

fn transaction_from_connection(
    connection: &Connection,
    id: TransactionId,
) -> Result<Transaction, JournalError> {
    let (stored_id, revision, state, serialized): (String, i64, String, String) = connection
        .query_row(
            "SELECT id, revision, state, json FROM transactions WHERE id = ?1",
            params![id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(JournalError::Database)?
        .ok_or_else(|| JournalError::NotFound {
            kind: "transaction".into(),
            id: id.to_string(),
        })?;
    deserialize_transaction_snapshot(&stored_id, revision, &state, &serialized)
}

fn deserialize_transaction_snapshot(
    stored_id: &str,
    stored_revision: i64,
    stored_state: &str,
    serialized: &str,
) -> Result<Transaction, JournalError> {
    let transaction: Transaction =
        serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    let revision = u64::try_from(stored_revision)
        .map_err(|_| JournalError::Invariant("transaction revision is negative".into()))?;
    if transaction.id.to_string() != stored_id
        || transaction.revision != revision
        || state_name(transaction.state) != stored_state
    {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("transaction snapshot `{stored_id}` disagrees with indexed state"),
        });
    }
    Ok(transaction)
}

fn deserialize_verified_object<T: DeserializeOwned + Serialize>(
    kind: &str,
    id: &str,
    serialized: &str,
    expected_digest: &str,
) -> Result<T, JournalError> {
    let value: T = serde_json::from_str(serialized).map_err(JournalError::Serialization)?;
    let actual = canonical_digest(&value).map_err(JournalError::Canonical)?;
    if actual != expected_digest {
        return Err(JournalError::Corrupt {
            sequence: None,
            reason: format!("immutable {kind} object `{id}` has a digest mismatch"),
        });
    }
    Ok(value)
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

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
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
        {
            let connection = journal.lock().unwrap();
            connection
                .execute(
                    "UPDATE objects SET canonical_json = json_set(canonical_json, '$.display_name', 'Tampered') WHERE kind = 'principal' AND id = ?1",
                    params![principal.id.to_string()],
                )
                .unwrap();
        }
        assert!(matches!(
            journal.get_object::<veyra_protocol::Principal>("principal", &principal.id.to_string()),
            Err(JournalError::Corrupt { .. })
        ));
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
    }

    #[test]
    fn duplicate_idempotency_returns_original_receipt() {
        let journal = journal();
        let tx_id = TransactionId::new();
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", "digest")
                .unwrap(),
            IdempotencyReservation::Acquired
        );
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", "digest")
                .unwrap(),
            IdempotencyReservation::InProgress
        );
        let receipt = journal.sign_receipt(unsigned_receipt(tx_id)).unwrap();
        journal
            .complete_execution("filesystem", "key", "digest", &receipt)
            .unwrap();
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", "digest")
                .unwrap(),
            IdempotencyReservation::Completed(Box::new(receipt))
        );
        assert_eq!(
            journal
                .reserve_execution("filesystem", "key", "different")
                .unwrap(),
            IdempotencyReservation::Conflict
        );
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
                        .reserve_execution("filesystem", "concurrent-key", "same-digest")
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
