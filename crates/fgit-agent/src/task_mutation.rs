//! Post-commit-aware execution of one task projection mutation.
//!
//! A durable task backend may apply a request before its adapter finishes
//! constructing or returning the observation. Consequently, a malformed
//! observation is not equivalent to a pre-commit refusal. [`apply_task_mutation`]
//! invokes the adapter exactly once and distinguishes:
//!
//! - definite backend refusal or ambiguity, returned as an error;
//! - a validated applied/identical-retry receipt;
//! - an observation that failed local validation after the backend may already
//!   have committed, returned as [`TaskMutationAttempt::NeedsReconciliation`].
//!
//! Callers must not retry the final case blindly. They retain the exact request
//! and observation and probe the backend by [`crate::TaskMutationRequestId`].

use core::fmt;

use crate::{
    TaskAdapterRefusal, TaskMutationObservation, TaskMutationReceipt, TaskMutationRefusal,
    TaskMutationRequest, TaskMutationRequestId, TaskProjectionAdapter,
};

/// Result after an adapter returned an observation for one mutation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskMutationAttempt {
    /// The adapter observation was fully validated.
    Applied(TaskMutationReceipt),
    /// The adapter returned an observation that failed local validation. The
    /// backend may already have committed, so the request must be probed and
    /// reconciled rather than replayed as a fresh mutation.
    NeedsReconciliation {
        /// Idempotent request whose durable result is uncertain locally.
        request_id: TaskMutationRequestId,
        /// Exact adapter observation retained for diagnosis and probing.
        observation: TaskMutationObservation,
        /// Local validation refusal.
        refusal: TaskMutationRefusal,
    },
}

impl TaskMutationAttempt {
    /// Returns the validated receipt when this attempt is fully admitted.
    #[must_use]
    pub const fn receipt(&self) -> Option<&TaskMutationReceipt> {
        match self {
            Self::Applied(receipt) => Some(receipt),
            Self::NeedsReconciliation { .. } => None,
        }
    }
}

/// Pre-observation refusal from the safe mutation executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskMutationAttemptRefusal {
    /// Adapter profile used the reserved all-zero identity; no mutation call was
    /// issued.
    ZeroAdapterIdentity,
    /// Backend/transport result. `Ambiguous` means the adapter must probe by
    /// request identity before any retry.
    Adapter(TaskAdapterRefusal),
}

impl fmt::Display for TaskMutationAttemptRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task mutation attempt refused: {self:?}")
    }
}

impl core::error::Error for TaskMutationAttemptRefusal {}

/// Invokes one task adapter exactly once and preserves post-commit uncertainty.
///
/// # Errors
///
/// Returns only failures known before a locally inspectable observation exists:
/// an invalid adapter identity, a definite adapter rejection/unavailability, or
/// an adapter-declared ambiguous durable outcome.
pub fn apply_task_mutation<A: TaskProjectionAdapter>(
    adapter: &mut A,
    request: &TaskMutationRequest,
) -> Result<TaskMutationAttempt, TaskMutationAttemptRefusal> {
    let adapter_identity = adapter.adapter_identity();
    if is_zero(&adapter_identity) {
        return Err(TaskMutationAttemptRefusal::ZeroAdapterIdentity);
    }
    let observation = adapter
        .mutate(request)
        .map_err(TaskMutationAttemptRefusal::Adapter)?;
    match TaskMutationReceipt::admit(request, observation.clone(), adapter_identity) {
        Ok(receipt) => Ok(TaskMutationAttempt::Applied(receipt)),
        Err(refusal) => Ok(TaskMutationAttempt::NeedsReconciliation {
            request_id: request.request_id(),
            observation,
            refusal,
        }),
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
