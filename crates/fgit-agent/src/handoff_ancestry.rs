//! Atomic current-head proof and receiver handoff acceptance.
//!
//! [`crate::AgentHandoffCapsule::accept_at_descendant_head`] validates an
//! already-minted ancestry receipt. Host code still needs a safe way to obtain
//! that proof from the exact authority slot the receiver claims is current.
//! This module performs those two steps as one operation:
//!
//! ```text
//! read + authenticate current HeadKey
//!     -> bounded exact predecessor walk to the capsule head
//!     -> exact receiver head/generation/token match
//!     -> same-head or descendant handoff acceptance
//! ```
//!
//! The current slot is compared with the receiver's complete authenticated read
//! before the proof is consumed. A host therefore cannot walk one store or slot
//! and accept a receiver situation from another merely because both expose the
//! same head body. The accepted value retains the ancestry receipt when the
//! path is nonzero.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityHeadAncestryRefusal, AuthorityStore, AuthorityVersionToken,
    HeadKey, read_current_authority_head_descendant,
    read_current_authority_head_descendant_async,
};
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId};

use crate::{
    AgentHandoffAcceptance, AgentHandoffCapsule, AgentInstanceId, AgentSituationReceipt,
    HandoffAcceptanceRefusal, HandoffTargetResolution, IntentRun,
};

/// Accepts a handoff against the exact current authority slot.
///
/// The current head is authenticated and walked back to the source capsule's
/// authority head under `max_hops`. The receiver's run must carry the exact
/// current head identity, generation, and backend version token returned by
/// that same store read.
///
/// # Errors
///
/// Separates authority-history refusal, receiver/current-slot substitution,
/// and ordinary handoff-acceptance refusal.
pub fn accept_handoff_at_current_authority<S>(
    store: &S,
    head_key: &HeadKey,
    capsule: &AgentHandoffCapsule,
    receiver_situation: &AgentSituationReceipt,
    receiver_run: &IntentRun,
    receiver_instance_id: AgentInstanceId,
    target_resolution: HandoffTargetResolution,
    max_hops: usize,
) -> Result<AgentHandoffAcceptance, CurrentAuthorityHandoffRefusal>
where
    S: AuthorityStore + ?Sized,
{
    let source = capsule.reconciliation().authority_read_receipt();
    let current = read_current_authority_head_descendant(
        store,
        head_key,
        source.repository_id(),
        source.authority_head_id(),
        source.authority_head_generation(),
        max_hops,
    )?;
    validate_receiver_current_slot(
        current.head_id(),
        current.body().generation,
        current.authenticated().receipt().token(),
        receiver_run,
    )?;
    if current.ancestry().hops() == 0 {
        capsule
            .accept(
                receiver_situation,
                receiver_run,
                receiver_instance_id,
                target_resolution,
            )
            .map_err(CurrentAuthorityHandoffRefusal::Acceptance)
    } else {
        capsule
            .accept_at_descendant_head(
                receiver_situation,
                receiver_run,
                receiver_instance_id,
                target_resolution,
                current.ancestry(),
            )
            .map_err(CurrentAuthorityHandoffRefusal::Acceptance)
    }
}

/// Asynchronous twin of [`accept_handoff_at_current_authority`].
///
/// The semantic checks and refusal ordering are the same; only authority I/O is
/// awaited.
///
/// # Errors
///
/// The same typed refusals as [`accept_handoff_at_current_authority`].
pub async fn accept_handoff_at_current_authority_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    capsule: &AgentHandoffCapsule,
    receiver_situation: &AgentSituationReceipt,
    receiver_run: &IntentRun,
    receiver_instance_id: AgentInstanceId,
    target_resolution: HandoffTargetResolution,
    max_hops: usize,
) -> Result<AgentHandoffAcceptance, CurrentAuthorityHandoffRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let source = capsule.reconciliation().authority_read_receipt();
    let current = read_current_authority_head_descendant_async(
        store,
        cx,
        head_key,
        source.repository_id(),
        source.authority_head_id(),
        source.authority_head_generation(),
        max_hops,
    )
    .await?;
    validate_receiver_current_slot(
        current.head_id(),
        current.body().generation,
        current.authenticated().receipt().token(),
        receiver_run,
    )?;
    if current.ancestry().hops() == 0 {
        capsule
            .accept(
                receiver_situation,
                receiver_run,
                receiver_instance_id,
                target_resolution,
            )
            .map_err(CurrentAuthorityHandoffRefusal::Acceptance)
    } else {
        capsule
            .accept_at_descendant_head(
                receiver_situation,
                receiver_run,
                receiver_instance_id,
                target_resolution,
                current.ancestry(),
            )
            .map_err(CurrentAuthorityHandoffRefusal::Acceptance)
    }
}

/// Why current-authority handoff acceptance failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentAuthorityHandoffRefusal {
    /// Current-head authentication or bounded ancestry walk failed.
    Authority(AuthorityHeadAncestryRefusal),
    /// Receiver run has no complete authenticated authority receipt.
    ReceiverAuthorityReceiptRequired,
    /// Receiver run names another current head or generation.
    ReceiverCurrentHeadMismatch {
        /// Head authenticated from the requested authority slot.
        expected_head: RepositoryAuthorityHeadId,
        /// Head retained by the receiver run.
        observed_head: RepositoryAuthorityHeadId,
        /// Generation authenticated from the requested slot.
        expected_generation: HeadGeneration,
        /// Generation retained by the receiver run.
        observed_generation: HeadGeneration,
    },
    /// Receiver run was authenticated against another slot version or store.
    ReceiverCurrentTokenMismatch {
        /// Exact token returned by the current authority read.
        expected: AuthorityVersionToken,
        /// Token retained by the receiver run.
        observed: AuthorityVersionToken,
    },
    /// Receiver-side handoff verification refused the complete inputs.
    Acceptance(HandoffAcceptanceRefusal),
}

impl fmt::Display for CurrentAuthorityHandoffRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(refusal) => write!(formatter, "current authority refused: {refusal}"),
            Self::ReceiverAuthorityReceiptRequired => formatter.write_str(
                "current-head handoff acceptance requires an authenticated receiver run",
            ),
            Self::ReceiverCurrentHeadMismatch { .. } => formatter.write_str(
                "receiver run does not name the head authenticated from the requested current slot",
            ),
            Self::ReceiverCurrentTokenMismatch { .. } => formatter.write_str(
                "receiver run does not carry the version token authenticated from the requested current slot",
            ),
            Self::Acceptance(refusal) => write!(formatter, "handoff acceptance refused: {refusal}"),
        }
    }
}

impl core::error::Error for CurrentAuthorityHandoffRefusal {}

impl From<AuthorityHeadAncestryRefusal> for CurrentAuthorityHandoffRefusal {
    fn from(value: AuthorityHeadAncestryRefusal) -> Self {
        Self::Authority(value)
    }
}

fn validate_receiver_current_slot(
    current_head_id: RepositoryAuthorityHeadId,
    current_generation: HeadGeneration,
    current_token: AuthorityVersionToken,
    receiver_run: &IntentRun,
) -> Result<(), CurrentAuthorityHandoffRefusal> {
    let receiver = receiver_run
        .authority_read_receipt()
        .ok_or(CurrentAuthorityHandoffRefusal::ReceiverAuthorityReceiptRequired)?;
    if receiver.authority_head_id() != current_head_id
        || receiver.authority_head_generation() != current_generation
    {
        return Err(CurrentAuthorityHandoffRefusal::ReceiverCurrentHeadMismatch {
            expected_head: current_head_id,
            observed_head: receiver.authority_head_id(),
            expected_generation: current_generation,
            observed_generation: receiver.authority_head_generation(),
        });
    }
    if receiver.backend_version_token() != current_token {
        return Err(CurrentAuthorityHandoffRefusal::ReceiverCurrentTokenMismatch {
            expected: current_token,
            observed: receiver.backend_version_token(),
        });
    }
    Ok(())
}
