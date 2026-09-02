//! Persistence-gated task claim and resolution applications.
//!
//! Semantic transition construction and claim admission are pure, but neither
//! proves that a durable task backend installed the successor. This module
//! enforces the ordering expected by the Agent Control Plane:
//!
//! 1. validate the authority-bound application and claim control objects;
//! 2. freeze the exact predecessor/successor mutation envelope;
//! 3. execute the one-shot store protocol;
//! 4. expose an activatable claim or cancellation projection only after the
//!    authenticated reread confirms the exact successor.
//!
//! Conflict and uncertain outcomes retain the complete envelope and typed store
//! execution for recovery. They never expose a claim receipt or cancellation
//! projection that downstream code could mistake for a persisted transition.

use core::fmt;

use crate::{
    AgentChangePlan, AgentControlPulse, AuthorityBoundTaskClaimApplication,
    AuthorityBoundTaskProjectionSnapshot, AuthorityBoundTaskProjectionTransition,
    AuthorityBoundTaskResolutionApplication, IntentRun, TaskClaimCancellationProjection,
    TaskClaimReceipt, TaskClaimRefusal, TaskProjectionMutationEnvelope,
    TaskProjectionPersistenceReceipt, TaskProjectionPersistenceRefusal, TaskProjectionStore,
    TaskProjectionStoreExecution, TaskProjectionStoreExecutionRefusal,
    TaskProjectionStoreFlushDisposition, TaskProjectionStoreWriteDisposition,
    execute_task_projection_store,
};

/// Successfully persisted claim, ready for post-claim situation activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedTaskClaim {
    envelope: TaskProjectionMutationEnvelope,
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    persistence_receipt: TaskProjectionPersistenceReceipt,
    claim_receipt: TaskClaimReceipt,
    write: TaskProjectionStoreWriteDisposition,
    flush: TaskProjectionStoreFlushDisposition,
}

impl PersistedTaskClaim {
    /// Exact predecessor/successor store request.
    #[must_use]
    pub const fn envelope(&self) -> &TaskProjectionMutationEnvelope {
        &self.envelope
    }

    /// Persisted successor state.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Repository-scoped transition audit receipt.
    #[must_use]
    pub const fn transition(&self) -> AuthorityBoundTaskProjectionTransition {
        self.transition
    }

    /// Authenticated persistence confirmation.
    #[must_use]
    pub const fn persistence_receipt(&self) -> TaskProjectionPersistenceReceipt {
        self.persistence_receipt
    }

    /// Claim receipt now safe to activate after a fresh situation observes the
    /// persisted generation.
    #[must_use]
    pub const fn claim_receipt(&self) -> &TaskClaimReceipt {
        &self.claim_receipt
    }

    /// Compare-and-replace disposition.
    #[must_use]
    pub const fn write_disposition(&self) -> TaskProjectionStoreWriteDisposition {
        self.write
    }

    /// Collaborative/read projection flush disposition.
    #[must_use]
    pub const fn flush_disposition(&self) -> TaskProjectionStoreFlushDisposition {
        self.flush
    }
}

/// Terminal outcome of one persistence-gated claim attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskClaimPersistenceOutcome {
    /// Exact successor persistence was confirmed and the claim may be activated
    /// by a later matching situation.
    Persisted(PersistedTaskClaim),
    /// Another task state was current and the exact envelope did not commit.
    Conflict {
        /// Complete request retained for audit/replanning.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed store conflict.
        execution: TaskProjectionStoreExecution,
    },
    /// A possible or historical effect remains unresolved.
    NeedsReconciliation {
        /// Complete request retained for exact recovery.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed store debt.
        execution: TaskProjectionStoreExecution,
    },
}

/// Successfully persisted release or transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedTaskResolution {
    envelope: TaskProjectionMutationEnvelope,
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    persistence_receipt: TaskProjectionPersistenceReceipt,
    cancellation_projection: TaskClaimCancellationProjection,
    write: TaskProjectionStoreWriteDisposition,
    flush: TaskProjectionStoreFlushDisposition,
}

impl PersistedTaskResolution {
    /// Exact predecessor/successor store request.
    #[must_use]
    pub const fn envelope(&self) -> &TaskProjectionMutationEnvelope {
        &self.envelope
    }

    /// Persisted successor state.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Repository-scoped transition audit receipt.
    #[must_use]
    pub const fn transition(&self) -> AuthorityBoundTaskProjectionTransition {
        self.transition
    }

    /// Authenticated persistence confirmation.
    #[must_use]
    pub const fn persistence_receipt(&self) -> TaskProjectionPersistenceReceipt {
        self.persistence_receipt
    }

    /// Cancellation/handoff projection now safe to consume because the exact
    /// release or transfer successor was confirmed.
    #[must_use]
    pub const fn cancellation_projection(&self) -> &TaskClaimCancellationProjection {
        &self.cancellation_projection
    }

    /// Compare-and-replace disposition.
    #[must_use]
    pub const fn write_disposition(&self) -> TaskProjectionStoreWriteDisposition {
        self.write
    }

    /// Collaborative/read projection flush disposition.
    #[must_use]
    pub const fn flush_disposition(&self) -> TaskProjectionStoreFlushDisposition {
        self.flush
    }
}

/// Terminal outcome of one persistence-gated release or transfer attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskResolutionPersistenceOutcome {
    /// Exact successor persistence was confirmed.
    Persisted(PersistedTaskResolution),
    /// Another task state was current and the exact envelope did not commit.
    Conflict {
        /// Complete request retained for audit/replanning.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed store conflict.
        execution: TaskProjectionStoreExecution,
    },
    /// A possible or historical effect remains unresolved.
    NeedsReconciliation {
        /// Complete request retained for exact recovery.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed store debt.
        execution: TaskProjectionStoreExecution,
    },
}

/// Pre-effect refusal from persistence-gated task application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskPersistenceGateRefusal {
    /// Exact mutation envelope could not be frozen.
    Persistence(TaskProjectionPersistenceRefusal),
    /// Claim control objects rejected the prepared projection before I/O.
    Claim(TaskClaimRefusal),
    /// Store refused before mutation or initial state retrieval.
    Store(TaskProjectionStoreExecutionRefusal),
    /// Store returned a result kind outside the closed execution vocabulary.
    UnexpectedStoreOutcome,
}

impl fmt::Display for TaskPersistenceGateRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "persistence-gated task application refused: {self:?}"
        )
    }
}

impl core::error::Error for TaskPersistenceGateRefusal {}

impl From<TaskProjectionPersistenceRefusal> for TaskPersistenceGateRefusal {
    fn from(value: TaskProjectionPersistenceRefusal) -> Self {
        Self::Persistence(value)
    }
}

impl From<TaskClaimRefusal> for TaskPersistenceGateRefusal {
    fn from(value: TaskClaimRefusal) -> Self {
        Self::Claim(value)
    }
}

impl From<TaskProjectionStoreExecutionRefusal> for TaskPersistenceGateRefusal {
    fn from(value: TaskProjectionStoreExecutionRefusal) -> Self {
        Self::Store(value)
    }
}

/// Persists one authority-bound claim and exposes the claim receipt only after
/// the exact successor is confirmed.
///
/// Claim admission is performed before store I/O, so pulse/plan/run mismatch can
/// never become a post-commit integration surprise.
///
/// # Errors
///
/// Refuses envelope construction, claim admission, or a definite pre-effect
/// store failure.
pub fn persist_task_claim<S: TaskProjectionStore>(
    store: &mut S,
    application: AuthorityBoundTaskClaimApplication,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
) -> Result<TaskClaimPersistenceOutcome, TaskPersistenceGateRefusal> {
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)?;
    let claim_receipt =
        TaskClaimReceipt::admit(pulse, plan, run, application.projection().clone())?;
    let snapshot = application.snapshot().clone();
    let transition = application.transition();

    match execute_task_projection_store(store, &envelope)? {
        TaskProjectionStoreExecution::Confirmed {
            receipt,
            write,
            flush,
        } => Ok(TaskClaimPersistenceOutcome::Persisted(PersistedTaskClaim {
            envelope,
            snapshot,
            transition,
            persistence_receipt: receipt,
            claim_receipt,
            write,
            flush,
        })),
        execution @ TaskProjectionStoreExecution::Conflict { .. } => {
            Ok(TaskClaimPersistenceOutcome::Conflict {
                envelope,
                execution,
            })
        }
        execution @ TaskProjectionStoreExecution::NeedsReconciliation { .. } => {
            Ok(TaskClaimPersistenceOutcome::NeedsReconciliation {
                envelope,
                execution,
            })
        }
    }
}

/// Persists one authority-bound release or transfer and exposes its cancellation
/// projection only after the exact successor is confirmed.
///
/// # Errors
///
/// Refuses envelope construction or a definite pre-effect store failure.
pub fn persist_task_resolution<S: TaskProjectionStore>(
    store: &mut S,
    application: AuthorityBoundTaskResolutionApplication,
) -> Result<TaskResolutionPersistenceOutcome, TaskPersistenceGateRefusal> {
    let envelope = TaskProjectionMutationEnvelope::from_resolution(&application)?;
    let snapshot = application.snapshot().clone();
    let transition = application.transition();
    let cancellation_projection = *application.projection();

    match execute_task_projection_store(store, &envelope)? {
        TaskProjectionStoreExecution::Confirmed {
            receipt,
            write,
            flush,
        } => Ok(TaskResolutionPersistenceOutcome::Persisted(
            PersistedTaskResolution {
                envelope,
                snapshot,
                transition,
                persistence_receipt: receipt,
                cancellation_projection,
                write,
                flush,
            },
        )),
        execution @ TaskProjectionStoreExecution::Conflict { .. } => {
            Ok(TaskResolutionPersistenceOutcome::Conflict {
                envelope,
                execution,
            })
        }
        execution @ TaskProjectionStoreExecution::NeedsReconciliation { .. } => {
            Ok(TaskResolutionPersistenceOutcome::NeedsReconciliation {
                envelope,
                execution,
            })
        }
    }
}
