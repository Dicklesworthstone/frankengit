//! One-call durable task-store orchestration without blind retry.
//!
//! [`crate::TaskProjectionMutationEnvelope`] contains the complete semantic
//! predecessor, desired successor, and evidence contract. This module defines
//! the storage-neutral protocol a concrete Beads or scheduler adapter must
//! implement around that envelope:
//!
//! 1. authenticated initial read;
//! 2. one exact-predecessor compare-and-replace;
//! 3. one explicit projection flush/no-op decision;
//! 4. authenticated confirming reread;
//! 5. complete-state reconciliation.
//!
//! The orchestrator never repeats the compare-and-replace call. An ambiguous
//! write is considered resolved only when the exact successor and metadata are
//! subsequently observed. Seeing the predecessor after an ambiguous write is
//! not labelled retry-safe because the timed-out operation may still be in
//! flight. A concrete adapter may later add an envelope-ID probe that proves
//! quiescence; this v1 protocol refuses to guess.
//!
//! Store traits are effect boundaries, not repository authority. Their definite
//! write refusals are contractually pre-mutation. Flush/read failures after a
//! possible write are returned as reconciliation debt, never as though no
//! effect happened.

use core::fmt;

use fgit_types::{Digest, RepositoryId};

use crate::{
    TaskProjectionMutationEnvelope, TaskProjectionMutationEnvelopeId,
    TaskProjectionPersistedState, TaskProjectionPersistenceDecision,
    TaskProjectionPersistenceReceipt, TaskProjectionPersistenceRefusal, WorkTaskId,
};

/// Repository/task address used by a durable task store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionStoreKey {
    repository_id: RepositoryId,
    task_id: WorkTaskId,
}

impl TaskProjectionStoreKey {
    /// Builds the exact task address.
    #[must_use]
    pub const fn new(repository_id: RepositoryId, task_id: WorkTaskId) -> Self {
        Self {
            repository_id,
            task_id,
        }
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Task identity.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }
}

impl From<&TaskProjectionMutationEnvelope> for TaskProjectionStoreKey {
    fn from(envelope: &TaskProjectionMutationEnvelope) -> Self {
        Self::new(envelope.repository_id(), envelope.task_id())
    }
}

/// Durable task-store boundary.
pub trait TaskProjectionStore {
    /// Stable implementation/profile identity. It must equal the adapter
    /// identity committed by the mutation envelope.
    fn adapter_identity(&self) -> [u8; 32];

    /// Authenticated current row read. The returned snapshot owns its complete
    /// authority-read provenance and structural task state.
    fn read(
        &mut self,
        key: TaskProjectionStoreKey,
    ) -> Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal>;

    /// Performs one exact-predecessor compare-and-replace.
    ///
    /// `Err` is a definite pre-mutation refusal. Uncertain transport outcomes
    /// must be returned as [`TaskProjectionStoreWriteOutcome::Ambiguous`].
    fn compare_and_replace(
        &mut self,
        envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal>;

    /// Flushes the backend's collaborative/read projection for this exact
    /// envelope, or reports that no separate flush is required.
    ///
    /// The method must never install the desired successor by itself. It may
    /// flush only state already current under the exact envelope.
    fn flush(
        &mut self,
        envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal>;
}

/// Result of the one compare-and-replace call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreWriteOutcome {
    /// This call installed the exact successor.
    Applied,
    /// The backend recognized the exact prior envelope result.
    IdenticalRetry,
    /// The exact predecessor was not current and no mutation occurred.
    PreconditionFailed,
    /// The backend cannot yet determine whether this envelope committed.
    Ambiguous {
        /// Commitment to backend probe/recovery context.
        probe_root: Digest,
    },
}

/// Result of the explicit projection flush step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreFlushOutcome {
    /// A separate collaborative/read projection was flushed.
    Flushed,
    /// The backend has no separate flush requirement or the exact successor was
    /// not current.
    NotRequired,
    /// The backend cannot yet determine whether the flush completed.
    Ambiguous {
        /// Commitment to backend probe/recovery context.
        probe_root: Digest,
    },
}

/// Write status retained by every terminal orchestration outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreWriteDisposition {
    /// No compare-and-replace call was needed because an initial read already
    /// observed the exact successor.
    NotAttempted,
    /// The call reported application.
    Applied,
    /// The call recognized an identical prior application.
    IdenticalRetry,
    /// The call definitely refused its predecessor comparison.
    PreconditionFailed,
    /// The write result was ambiguous.
    Ambiguous {
        /// Backend recovery commitment.
        probe_root: Digest,
    },
}

impl From<TaskProjectionStoreWriteOutcome> for TaskProjectionStoreWriteDisposition {
    fn from(value: TaskProjectionStoreWriteOutcome) -> Self {
        match value {
            TaskProjectionStoreWriteOutcome::Applied => Self::Applied,
            TaskProjectionStoreWriteOutcome::IdenticalRetry => Self::IdenticalRetry,
            TaskProjectionStoreWriteOutcome::PreconditionFailed => Self::PreconditionFailed,
            TaskProjectionStoreWriteOutcome::Ambiguous { probe_root } => {
                Self::Ambiguous { probe_root }
            }
        }
    }
}

/// Flush status retained by every terminal orchestration outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreFlushDisposition {
    /// Flush was not reached.
    NotAttempted,
    /// Flush completed.
    Flushed,
    /// No separate flush was required.
    NotRequired,
    /// Flush result is ambiguous.
    Ambiguous {
        /// Backend recovery commitment.
        probe_root: Digest,
    },
    /// Flush was definitely refused after the task mutation may have committed.
    Refused(TaskProjectionStoreFlushRefusal),
}

impl TaskProjectionStoreFlushDisposition {
    fn is_definite_success(self) -> bool {
        matches!(self, Self::Flushed | Self::NotRequired)
    }
}

/// Final result of one bounded store attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreExecution {
    /// Exact successor persistence and required flush were confirmed.
    Confirmed {
        /// Persistence receipt from the authenticated reread.
        receipt: TaskProjectionPersistenceReceipt,
        /// Compare-and-replace disposition.
        write: TaskProjectionStoreWriteDisposition,
        /// Flush disposition.
        flush: TaskProjectionStoreFlushDisposition,
    },
    /// No mutation was attempted and another state was already current.
    Conflict {
        /// Exact envelope that was not applied.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Compare-and-replace disposition, normally `NotAttempted` or
        /// `PreconditionFailed`.
        write: TaskProjectionStoreWriteDisposition,
        /// Current conflicting snapshot.
        current_snapshot_id: crate::AuthorityBoundTaskProjectionSnapshotId,
        /// Current conflicting generation.
        current_generation: [u8; 32],
    },
    /// A possible or definite side effect lacks enough evidence for a completed
    /// result. The exact envelope must be probed/reconciled; it must not be
    /// reconstructed as a new request.
    NeedsReconciliation {
        /// Exact envelope requiring recovery.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Stage at which certainty was lost.
        stage: TaskProjectionStoreStage,
        /// Compare-and-replace disposition.
        write: TaskProjectionStoreWriteDisposition,
        /// Flush disposition.
        flush: TaskProjectionStoreFlushDisposition,
        /// Reread interpretation when one was available.
        decision: Option<TaskProjectionPersistenceDecision>,
        /// Primary typed reason certainty is incomplete.
        cause: TaskProjectionStoreReconciliationCause,
    },
}

/// Store stage used by reconciliation evidence and refusals.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskProjectionStoreStage {
    /// Initial authenticated read before any write.
    InitialRead,
    /// Exact-predecessor compare-and-replace.
    CompareAndReplace,
    /// Collaborative/read projection flush.
    Flush,
    /// Authenticated reread after the attempt.
    ConfirmingRead,
    /// Complete-state interpretation of a reread.
    Reconcile,
}

/// Why a post-effect attempt remains unresolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreReconciliationCause {
    /// Initial state was already mixed/corrupt from an earlier attempt.
    InitialPersistence(TaskProjectionPersistenceRefusal),
    /// Flush result was ambiguous.
    FlushAmbiguous {
        /// Backend recovery commitment.
        probe_root: Digest,
    },
    /// Flush was definitely refused after persistence may have occurred.
    FlushRefused(TaskProjectionStoreFlushRefusal),
    /// Confirming read failed.
    ConfirmingRead(TaskProjectionStoreReadRefusal),
    /// Confirming read found no row.
    ProjectionMissing,
    /// Complete-state reconciliation refused the observed row.
    Persistence(TaskProjectionPersistenceRefusal),
    /// An ambiguous write was followed by a non-successor row; absence of the
    /// successor does not prove the timed-out operation is quiescent.
    AmbiguousWriteUnresolved,
    /// A definite write result contradicted the confirming row.
    BackendContradiction,
    /// A possible committed result was later replaced; current-row state alone
    /// cannot prove whether this envelope briefly committed.
    HistoryRequired,
}

/// Definite read refusal. Reads never mutate task state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreReadRefusal {
    /// Backend or authenticated read path is unavailable.
    Unavailable,
    /// Backend policy refused disclosure.
    Policy,
    /// Backend returned a row it could not authenticate or structurally decode.
    Corrupt,
}

/// Definite pre-mutation write refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreWriteRefusal {
    /// Backend was unavailable before accepting the request.
    Unavailable,
    /// Policy definitely rejected the request.
    Policy,
    /// Backend profile does not support exact-predecessor replacement.
    Unsupported,
}

/// Definite flush refusal after task persistence may already have occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreFlushRefusal {
    /// Flush path was unavailable.
    Unavailable,
    /// Policy refused the flush.
    Policy,
    /// Backend profile has an external projection but cannot flush it.
    Unsupported,
}

/// Pre-effect refusal from task-store orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionStoreExecutionRefusal {
    /// Store identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Store profile differs from the profile committed by the envelope.
    AdapterIdentityMismatch {
        /// Envelope profile.
        expected: [u8; 32],
        /// Invoked store profile.
        observed: [u8; 32],
    },
    /// Initial authenticated read failed before any write.
    InitialRead(TaskProjectionStoreReadRefusal),
    /// Initial read found no exact predecessor row.
    InitialProjectionMissing,
    /// Compare-and-replace definitely refused before mutation.
    Write(TaskProjectionStoreWriteRefusal),
}

impl fmt::Display for TaskProjectionStoreExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task-store execution refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionStoreExecutionRefusal {}

/// Executes one bounded durable task-store attempt.
///
/// The function performs at most one compare-and-replace and never retries it.
///
/// # Errors
///
/// Returns only conditions known before mutation: invalid store identity,
/// initial read failure/missing predecessor, or a definite pre-mutation write
/// refusal. Every uncertainty after a possible effect is returned as
/// [`TaskProjectionStoreExecution::NeedsReconciliation`].
pub fn execute_task_projection_store<S: TaskProjectionStore>(
    store: &mut S,
    envelope: &TaskProjectionMutationEnvelope,
) -> Result<TaskProjectionStoreExecution, TaskProjectionStoreExecutionRefusal> {
    let adapter_identity = store.adapter_identity();
    if is_zero(&adapter_identity) {
        return Err(TaskProjectionStoreExecutionRefusal::ZeroAdapterIdentity);
    }
    if adapter_identity != envelope.adapter_identity() {
        return Err(TaskProjectionStoreExecutionRefusal::AdapterIdentityMismatch {
            expected: envelope.adapter_identity(),
            observed: adapter_identity,
        });
    }

    let key = TaskProjectionStoreKey::from(envelope);
    let initial = store
        .read(key)
        .map_err(TaskProjectionStoreExecutionRefusal::InitialRead)?;
    let Some(initial) = initial else {
        return Err(TaskProjectionStoreExecutionRefusal::InitialProjectionMissing);
    };
    match envelope.reconcile(Some(&initial)) {
        Ok(TaskProjectionPersistenceDecision::Confirmed(_)) => {
            return finish_attempt(
                store,
                envelope,
                TaskProjectionStoreWriteDisposition::NotAttempted,
            );
        }
        Ok(TaskProjectionPersistenceDecision::RetrySafe { .. }) => {}
        Ok(TaskProjectionPersistenceDecision::Conflict {
            current_snapshot_id,
            current_generation,
            ..
        }) => {
            return Ok(TaskProjectionStoreExecution::Conflict {
                envelope_id: envelope.envelope_id(),
                write: TaskProjectionStoreWriteDisposition::NotAttempted,
                current_snapshot_id,
                current_generation,
            });
        }
        Err(refusal) => {
            return Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id(),
                stage: TaskProjectionStoreStage::InitialRead,
                write: TaskProjectionStoreWriteDisposition::NotAttempted,
                flush: TaskProjectionStoreFlushDisposition::NotAttempted,
                decision: None,
                cause: TaskProjectionStoreReconciliationCause::InitialPersistence(refusal),
            });
        }
    }

    let write = store
        .compare_and_replace(envelope)
        .map_err(TaskProjectionStoreExecutionRefusal::Write)?;
    finish_attempt(store, envelope, write.into())
}

fn finish_attempt<S: TaskProjectionStore>(
    store: &mut S,
    envelope: &TaskProjectionMutationEnvelope,
    write: TaskProjectionStoreWriteDisposition,
) -> Result<TaskProjectionStoreExecution, TaskProjectionStoreExecutionRefusal> {
    let flush = match store.flush(envelope) {
        Ok(TaskProjectionStoreFlushOutcome::Flushed) => {
            TaskProjectionStoreFlushDisposition::Flushed
        }
        Ok(TaskProjectionStoreFlushOutcome::NotRequired) => {
            TaskProjectionStoreFlushDisposition::NotRequired
        }
        Ok(TaskProjectionStoreFlushOutcome::Ambiguous { probe_root }) => {
            TaskProjectionStoreFlushDisposition::Ambiguous { probe_root }
        }
        Err(refusal) => TaskProjectionStoreFlushDisposition::Refused(refusal),
    };

    let key = TaskProjectionStoreKey::from(envelope);
    let observed = match store.read(key) {
        Ok(Some(observed)) => observed,
        Ok(None) => {
            return Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id(),
                stage: TaskProjectionStoreStage::ConfirmingRead,
                write,
                flush,
                decision: None,
                cause: TaskProjectionStoreReconciliationCause::ProjectionMissing,
            });
        }
        Err(refusal) => {
            return Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id(),
                stage: TaskProjectionStoreStage::ConfirmingRead,
                write,
                flush,
                decision: None,
                cause: TaskProjectionStoreReconciliationCause::ConfirmingRead(refusal),
            });
        }
    };
    let decision = match envelope.reconcile(Some(&observed)) {
        Ok(decision) => decision,
        Err(refusal) => {
            return Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id(),
                stage: TaskProjectionStoreStage::Reconcile,
                write,
                flush,
                decision: None,
                cause: TaskProjectionStoreReconciliationCause::Persistence(refusal),
            });
        }
    };

    if !flush.is_definite_success() {
        let cause = match flush {
            TaskProjectionStoreFlushDisposition::Ambiguous { probe_root } => {
                TaskProjectionStoreReconciliationCause::FlushAmbiguous { probe_root }
            }
            TaskProjectionStoreFlushDisposition::Refused(refusal) => {
                TaskProjectionStoreReconciliationCause::FlushRefused(refusal)
            }
            TaskProjectionStoreFlushDisposition::NotAttempted
            | TaskProjectionStoreFlushDisposition::Flushed
            | TaskProjectionStoreFlushDisposition::NotRequired => {
                TaskProjectionStoreReconciliationCause::BackendContradiction
            }
        };
        return Ok(TaskProjectionStoreExecution::NeedsReconciliation {
            envelope_id: envelope.envelope_id(),
            stage: TaskProjectionStoreStage::Flush,
            write,
            flush,
            decision: Some(decision),
            cause,
        });
    }

    match decision {
        TaskProjectionPersistenceDecision::Confirmed(receipt) => {
            Ok(TaskProjectionStoreExecution::Confirmed {
                receipt,
                write,
                flush,
            })
        }
        TaskProjectionPersistenceDecision::RetrySafe { .. } => {
            let cause = if matches!(
                write,
                TaskProjectionStoreWriteDisposition::Ambiguous { .. }
            ) {
                TaskProjectionStoreReconciliationCause::AmbiguousWriteUnresolved
            } else {
                TaskProjectionStoreReconciliationCause::BackendContradiction
            };
            Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id(),
                stage: TaskProjectionStoreStage::Reconcile,
                write,
                flush,
                decision: Some(decision),
                cause,
            })
        }
        TaskProjectionPersistenceDecision::Conflict {
            current_snapshot_id,
            current_generation,
            ..
        } => {
            if matches!(
                write,
                TaskProjectionStoreWriteDisposition::NotAttempted
                    | TaskProjectionStoreWriteDisposition::PreconditionFailed
            ) {
                Ok(TaskProjectionStoreExecution::Conflict {
                    envelope_id: envelope.envelope_id(),
                    write,
                    current_snapshot_id,
                    current_generation,
                })
            } else {
                Ok(TaskProjectionStoreExecution::NeedsReconciliation {
                    envelope_id: envelope.envelope_id(),
                    stage: TaskProjectionStoreStage::Reconcile,
                    write,
                    flush,
                    decision: Some(decision),
                    cause: TaskProjectionStoreReconciliationCause::HistoryRequired,
                })
            }
        }
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
