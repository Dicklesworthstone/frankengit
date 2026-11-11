//! Latest net ref change from one authenticated decision-history suffix.
//!
//! The watch profile is batch-net: a microbatch's predecessor and successor
//! ref states define one event, even if several RCRs touch the watched ref.
//! The exact predecessor map also supplies its old tip, so earlier history and
//! unrelated forge/outbox payloads are not prerequisites for selecting that event.

use fgit_authority::{AsyncAuthorityStore, MAX_REPLAY_BATCHES, OutcomeFailure};
use fgit_chronicle::PublicationBasis;
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId, RepositoryDecisionBatchId};

use crate::{
    AdmissionMaterializationRefusal, authority_head_id, capsule_history,
    read_historical_ref_state_in,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LatestRefChange {
    pub(super) previous_tip: Option<GitOid>,
    pub(super) batch_id: RepositoryDecisionBatchId,
    pub(super) resulting_head_id: RepositoryAuthorityHeadId,
}

/// The caller owns this already-authenticated basis and current visibility.
/// No cached position or request field supplies an event identity. The bound
/// may narrow the shared snapshot-history profile, but cannot increase it.
pub(super) async fn latest_change_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    reference: &RefName,
    tip: GitOid,
    maximum_steps: usize,
    cancelled: &C,
) -> Result<LatestRefChange, AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if maximum_steps == 0 || maximum_steps > MAX_REPLAY_BATCHES {
        return Err(bound(maximum_steps));
    }
    if authority_head_id(basis.body())? != basis.id() {
        return Err(AdmissionMaterializationRefusal::ExactBasisMismatch);
    }
    let repository = basis.body().repository_id;
    let current = read_historical_ref_state_in(store, cx, repository, basis.body()).await?;
    checkpoint(cancelled)?;
    if current.refs().get(reference) != Some(&tip) {
        return Err(AdmissionMaterializationRefusal::ExactBasisMismatch);
    }

    drop(current);

    let mut successor = basis.body().clone();
    let mut successor_id = basis.id();
    let mut walked = 0usize;
    loop {
        checkpoint(cancelled)?;
        if walked >= maximum_steps {
            return Err(bound(maximum_steps));
        }
        let predecessor =
            match capsule_history::predecessor_in(store, cx, &successor, &mut walked, cancelled)
                .await?
            {
                capsule_history::HistoryStep::Genesis => {
                    // A preseeded or missing ref history is not a new push event.
                    return Err(AdmissionMaterializationRefusal::DecisionHistoryUnbound);
                }
                capsule_history::HistoryStep::Checkpoint { predecessor, .. } => {
                    // The verified checkpoint preserves refs and invents no event.
                    successor_id = predecessor.id();
                    successor = predecessor.body().clone();
                    continue;
                }
                capsule_history::HistoryStep::Decision { predecessor, .. } => predecessor,
            };
        checkpoint(cancelled)?;
        if predecessor.body().ref_root != successor.ref_root {
            let previous =
                read_historical_ref_state_in(store, cx, repository, predecessor.body()).await?;
            checkpoint(cancelled)?;
            let previous_tip = previous.refs().get(reference).copied();
            if previous_tip != Some(tip) {
                let batch_id = successor
                    .decision_tail_id
                    .ok_or(AdmissionMaterializationRefusal::DecisionHistoryUnbound)?;
                return Ok(LatestRefChange {
                    previous_tip,
                    batch_id,
                    resulting_head_id: successor_id,
                });
            }
        }
        // Every later verified head has the selected tip. A change to another
        // ref, a ref identity operation, and an intra-batch return to the same
        // tip cannot become this watch's event.
        successor_id = predecessor.id();
        successor = predecessor.body().clone();
    }
}

fn checkpoint(
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<(), AdmissionMaterializationRefusal> {
    if cancelled() {
        Err(AdmissionMaterializationRefusal::Cancelled)
    } else {
        Ok(())
    }
}

fn bound(limit: usize) -> AdmissionMaterializationRefusal {
    AdmissionMaterializationRefusal::DecisionHistory(Box::new(
        OutcomeFailure::ReplayBoundExceeded { limit },
    ))
}

#[cfg(test)]
mod tests;
