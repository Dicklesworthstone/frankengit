//! Bridge from collected task rows to the authority-bound claim basis.
//!
//! [`crate::TaskProjectionCollectionReceipt`] owns a complete multi-row
//! generation for frontier construction. [`crate::AuthorityBoundTaskProjectionSnapshot`]
//! owns one exact task state for claim/release/transfer semantics. This module
//! connects the two only where the collected row is sufficient by construction:
//! an unassigned task with no active claim metadata.
//!
//! Claimed or assigned rows require durable lease history including the claim
//! predecessor generation and claim instant. The v1 collected row does not
//! retain all of that history, so this bridge refuses rather than fabricating it.
//! A production backend reconstructs those rows through
//! [`crate::AuthorityBoundTaskProjectionSnapshot::observed_with_lease`].

use core::fmt;

use crate::{
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadIdentityRefusal,
    AuthorityReadReceipt, TaskCoordinationRefusal, TaskProjectionAssignment,
    TaskProjectionCollectionReceipt, WorkTaskId,
};

/// Converts one collected unassigned row into the exact authority-bound claim
/// basis.
///
/// # Errors
///
/// Refuses another authenticated read event, a missing task, any assignment or
/// active-claim metadata, and authority-bound snapshot construction failure.
pub fn collected_unclaimed_task(
    collection: &TaskProjectionCollectionReceipt,
    authority: &AuthorityReadReceipt,
    task_id: WorkTaskId,
) -> Result<AuthorityBoundTaskProjectionSnapshot, TaskCollectionBridgeRefusal> {
    let authority_read_receipt_id = authority.receipt_id()?;
    if authority_read_receipt_id != collection.authority_read_receipt_id()
        || authority.repository_id() != collection.repository_id()
        || authority.authority_head_id() != collection.authority_head_id()
        || authority.authority_head_generation() != collection.authority_head_generation()
    {
        return Err(TaskCollectionBridgeRefusal::AuthorityMismatch);
    }

    let row = collection
        .snapshot()
        .row(task_id)
        .ok_or(TaskCollectionBridgeRefusal::TaskMissing { task_id })?;
    if row.assignee().is_some()
        || row.plan_id().is_some()
        || row.claim_expiry().is_some()
        || !row.reserved_surfaces().is_empty()
    {
        return Err(TaskCollectionBridgeRefusal::LeaseReconstructionRequired {
            task_id,
        });
    }

    AuthorityBoundTaskProjectionSnapshot::observed(
        authority,
        task_id,
        *collection.snapshot().generation().as_bytes(),
        row.phase(),
        TaskProjectionAssignment::Unassigned,
        collection.snapshot().observed_at(),
    )
    .map_err(TaskCollectionBridgeRefusal::Coordination)
}

/// Why a collected row could not become an authority-bound claim basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCollectionBridgeRefusal {
    /// Caller supplied another authenticated read event or authority position.
    AuthorityMismatch,
    /// Requested task is absent from the collected generation.
    TaskMissing {
        /// Missing task identity.
        task_id: WorkTaskId,
    },
    /// The row carries assignment/claim state but not the complete durable lease
    /// history required for safe reconstruction.
    LeaseReconstructionRequired {
        /// Claimed or assigned task.
        task_id: WorkTaskId,
    },
    /// Exact authenticated-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Authority-bound single-task construction failed.
    Coordination(TaskCoordinationRefusal),
}

impl fmt::Display for TaskCollectionBridgeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task collection bridge refused: {self:?}")
    }
}

impl core::error::Error for TaskCollectionBridgeRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskCollectionBridgeRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}
