//! Retained forge pagination without a mutable cursor cache or a second head.
//!
//! The caller supplies the CURRENT basis from node-owned authenticated
//! materialization, not a client-created PublicationBasis. A client token is
//! only a requested ancestor identity: never fetch it directly or accept an
//! arbitrary stored head as published. Every traversed transition is verified
//! by the existing chronicle contract before any historical metadata is read.

use fgit_admission::AdmissionError;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId};

const MAX_SNAPSHOT_TRANSITIONS: usize = 256;
const MAX_SNAPSHOT_DECISIONS: usize = 65_536;

#[derive(Debug)]
pub(crate) enum SnapshotReadRefusal {
    /// Unknown, too old, or across an unsupported policy/retention boundary.
    /// This never authorizes silently substituting the current snapshot.
    Unavailable,
    /// Missing/corrupt evidence and cancellation are not snapshot absence.
    Admission(Box<AdmissionError>),
}

impl From<AdmissionError> for SnapshotReadRefusal {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(Box::new(error))
    }
}

fn stopped(cancelled: &impl Fn() -> bool) -> Result<(), SnapshotReadRefusal> {
    if cancelled() {
        Err(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress).into())
    } else {
        Ok(())
    }
}

fn invalid() -> SnapshotReadRefusal {
    AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid).into()
}

/// Only ordinary publications in one policy/configuration/retention epoch are
/// traversable. In particular, a revoked visibility policy cannot be bypassed
/// using an older page token, even if its old immutable objects still exist.
fn same_read_epoch(current: &RepositoryAuthorityHeadBody, older: &RepositoryAuthorityHeadBody) -> bool {
    current.repository_id == older.repository_id
        && current.configuration_root == older.configuration_root
        && current.policy_epoch == older.policy_epoch
        && current.format_registry_epoch == older.format_registry_epoch
        && current.last_checkpoint_id == older.last_checkpoint_id
}

pub(crate) async fn select<S, C>(
    store: &S,
    cx: &S::Context,
    current: &PublicationBasis,
    requested: Option<RepositoryAuthorityHeadId>,
    cancelled: &C,
) -> Result<PublicationBasis, SnapshotReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    select_bounded(store, cx, current, requested, MAX_SNAPSHOT_TRANSITIONS, cancelled).await
}

async fn select_bounded<S, C>(
    store: &S,
    cx: &S::Context,
    current: &PublicationBasis,
    requested: Option<RepositoryAuthorityHeadId>,
    maximum_transitions: usize,
    cancelled: &C,
) -> Result<PublicationBasis, SnapshotReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    stopped(cancelled)?;
    let wanted = requested.unwrap_or_else(|| current.id());
    let mut selected = current.clone();
    let mut transitions = 0usize;
    let mut decisions = 0usize;
    while selected.id() != wanted {
        stopped(cancelled)?;
        if transitions >= maximum_transitions {
            return Err(SnapshotReadRefusal::Unavailable);
        }
        let Some(predecessor_id) = selected.body().predecessor_head_id else {
            return Err(SnapshotReadRefusal::Unavailable);
        };
        let predecessor = fgit_authority::read_authority_head_body_async(store, cx, predecessor_id)
            .await.map_err(AdmissionError::from)?;
        stopped(cancelled)?;
        if !same_read_epoch(current.body(), &predecessor) {
            return Err(SnapshotReadRefusal::Unavailable);
        }
        let batch_id = selected.body().decision_tail_id.ok_or_else(invalid)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id)
            .await.map_err(AdmissionError::from)?;
        stopped(cancelled)?;
        let older = PublicationBasis::new(predecessor_id, predecessor);
        verify_pair(&CryptoBodyIdentity, &older, &batch, selected.body())
            .map_err(|_| invalid())?;
        // The current bounded profile has no historical retention lease.
        // Do not walk through compaction/generation activation on the strength
        // of an old token. Such continuations require a future retained-view
        // capability rather than interpreting object presence as permission.
        if batch.compaction_generation_link.is_some() {
            return Err(SnapshotReadRefusal::Unavailable);
        }
        decisions = decisions.checked_add(batch.decisions.len())
            .filter(|count| *count <= MAX_SNAPSHOT_DECISIONS)
            .ok_or(SnapshotReadRefusal::Unavailable)?;
        transitions += 1;
        selected = older;
    }
    stopped(cancelled)?;
    Ok(selected)
}

#[cfg(test)]
#[path = "metadata_snapshot_tests.rs"]
mod tests;
