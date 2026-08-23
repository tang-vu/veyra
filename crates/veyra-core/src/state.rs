//! Explicit transaction transition graph.

use chrono::Utc;
use thiserror::Error;
use veyra_protocol::{Transaction, TransactionId, TransactionState};

/// Typed transaction state machine.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateMachine;

impl StateMachine {
    /// Return whether the directed transition is part of Veyra's state graph.
    pub const fn allows(from: TransactionState, to: TransactionState) -> bool {
        use TransactionState as S;
        matches!(
            (from, to),
            (S::Draft, S::Planned | S::Cancelled)
                | (S::Planned, S::Preflighted | S::Failed | S::Cancelled)
                | (
                    S::Preflighted,
                    S::AwaitingApproval | S::Approved | S::Denied | S::Failed | S::Cancelled
                )
                | (S::AwaitingApproval, S::Approved | S::Denied | S::Cancelled)
                | (S::Approved, S::Staged | S::Failed | S::Cancelled)
                | (
                    S::Staged,
                    S::Executing | S::Compensating | S::Cancelled | S::Failed
                )
                | (
                    S::Executing,
                    S::Verifying | S::Failed | S::Compensating | S::ManualRecovery
                )
                | (
                    S::Verifying,
                    S::Committed | S::Failed | S::Compensating | S::ManualRecovery
                )
                | (S::Committed | S::ManualRecovery, S::Compensating)
                | (S::Failed, S::Compensating | S::ManualRecovery)
                | (
                    S::Compensating,
                    S::RolledBack | S::PartiallyCompensated | S::ManualRecovery | S::Failed
                )
        )
    }

    /// Apply one transition with optimistic revision checking.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::RevisionConflict`] if the caller observed a stale revision,
    /// or [`TransitionError::Invalid`] when the edge is absent from the state graph.
    pub fn transition(
        transaction: &mut Transaction,
        expected_revision: u64,
        next: TransactionState,
    ) -> Result<(), TransitionError> {
        if transaction.revision != expected_revision {
            return Err(TransitionError::RevisionConflict {
                transaction_id: transaction.id,
                expected: expected_revision,
                actual: transaction.revision,
            });
        }
        if !Self::allows(transaction.state, next) {
            return Err(TransitionError::Invalid {
                transaction_id: transaction.id,
                from: transaction.state,
                to: next,
            });
        }

        transaction.state = next;
        transaction.revision += 1;
        transaction.updated_at = Utc::now();
        if next != TransactionState::ManualRecovery {
            transaction.manual_recovery_reason = None;
        }
        Ok(())
    }

    /// Move a transaction to manual recovery and record a safe explanation.
    ///
    /// # Errors
    ///
    /// Returns a typed transition error under the same conditions as [`Self::transition`].
    pub fn require_manual_recovery(
        transaction: &mut Transaction,
        expected_revision: u64,
        reason: impl Into<String>,
    ) -> Result<(), TransitionError> {
        Self::transition(
            transaction,
            expected_revision,
            TransactionState::ManualRecovery,
        )?;
        transaction.manual_recovery_reason = Some(reason.into());
        Ok(())
    }
}

/// A rejected state transition.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    /// The requested directed edge is absent from the explicit state graph.
    #[error("transaction {transaction_id} cannot transition from {from:?} to {to:?}")]
    Invalid {
        /// Transaction being modified.
        transaction_id: TransactionId,
        /// Current state.
        from: TransactionState,
        /// Requested state.
        to: TransactionState,
    },
    /// The transaction changed after the caller read it.
    #[error("transaction {transaction_id} revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict {
        /// Transaction being modified.
        transaction_id: TransactionId,
        /// Revision observed by the caller.
        expected: u64,
        /// Current revision.
        actual: u64,
    },
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use proptest::prelude::*;
    use veyra_protocol::{IntentId, PROTOCOL_VERSION, PlanId};

    use super::*;

    const STATES: [TransactionState; 16] = [
        TransactionState::Draft,
        TransactionState::Planned,
        TransactionState::Preflighted,
        TransactionState::AwaitingApproval,
        TransactionState::Approved,
        TransactionState::Staged,
        TransactionState::Executing,
        TransactionState::Verifying,
        TransactionState::Committed,
        TransactionState::Denied,
        TransactionState::Failed,
        TransactionState::Compensating,
        TransactionState::RolledBack,
        TransactionState::PartiallyCompensated,
        TransactionState::Cancelled,
        TransactionState::ManualRecovery,
    ];

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
            revision: 7,
            created_at: now,
            updated_at: now,
            manual_recovery_reason: None,
        }
    }

    #[test]
    fn happy_path_is_explicit() {
        let path = [
            TransactionState::Draft,
            TransactionState::Planned,
            TransactionState::Preflighted,
            TransactionState::AwaitingApproval,
            TransactionState::Approved,
            TransactionState::Staged,
            TransactionState::Executing,
            TransactionState::Verifying,
            TransactionState::Committed,
        ];
        let mut tx = transaction(path[0]);
        for next in &path[1..] {
            let revision = tx.revision;
            StateMachine::transition(&mut tx, revision, *next).unwrap();
        }
        assert_eq!(tx.state, TransactionState::Committed);
        assert_eq!(tx.revision, 15);
    }

    #[test]
    fn stale_revision_cannot_mutate_state() {
        let mut tx = transaction(TransactionState::Draft);
        let original = tx.clone();
        assert!(matches!(
            StateMachine::transition(&mut tx, 6, TransactionState::Planned),
            Err(TransitionError::RevisionConflict { .. })
        ));
        assert_eq!(tx, original);
    }

    proptest! {
        #[test]
        fn invalid_edges_never_mutate(from in 0usize..STATES.len(), to in 0usize..STATES.len()) {
            let from = STATES[from];
            let to = STATES[to];
            let mut tx = transaction(from);
            let original = tx.clone();
            let result = StateMachine::transition(&mut tx, 7, to);
            if StateMachine::allows(from, to) {
                prop_assert!(result.is_ok());
                prop_assert_eq!(tx.state, to);
                prop_assert_eq!(tx.revision, 8);
            } else {
                let invalid = matches!(result, Err(TransitionError::Invalid { .. }));
                prop_assert!(invalid);
                prop_assert_eq!(tx, original);
            }
        }
    }
}
