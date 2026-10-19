//! One bounded authenticated head edge for native decision-history readers.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, ImmutableRead, MAX_REPLAY_BATCHES, OutcomeFailure,
    body_key_for_id, read_authority_head_body_async, read_decision_batch_body_async,
};
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_types::RepositoryCapsuleId;

use crate::{ChronicleRefusal, PublicationBasis, verify_pair};

use super::{CheckpointTransitionRefusal, verify_checkpoint_successor};

/// The predecessor of an authenticated head, after verifying its transition.
/// A checkpoint preserves decision state and must never manufacture a batch.
#[derive(Debug)]
pub enum HistoryStep {
    /// A head without predecessor or decision tail.
    Genesis,
    /// The exact capsule activation of the returned predecessor.
    Checkpoint { predecessor: PublicationBasis },
    /// A new decision batch verified against the returned predecessor.
    Decision {
        predecessor: PublicationBasis,
        batch: RepositoryDecisionBatchBody,
    },
}

/// No partial history step is returned on cancellation, ambiguity, or bad data.
#[derive(Debug)]
pub enum HistoryStepRefusal {
    Cancelled,
    BoundExceeded { limit: usize },
    UnboundHead,
    Authority(AuthorityFailure),
    Body(Box<OutcomeFailure>),
    CapsuleAbsent(RepositoryCapsuleId),
    Checkpoint(Box<CheckpointTransitionRefusal>),
    Decision(ChronicleRefusal),
}

impl fmt::Display for HistoryStepRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => out.write_str("authority history read was cancelled"),
            Self::BoundExceeded { limit } => {
                write!(out, "authority history exceeded {limit} predecessor edges")
            }
            Self::UnboundHead => out.write_str("authority history omitted a required predecessor"),
            Self::Authority(error) => fmt::Display::fmt(error, out),
            Self::Body(error) => fmt::Display::fmt(error, out),
            Self::CapsuleAbsent(id) => write!(out, "checkpoint capsule {id} is absent"),
            Self::Checkpoint(error) => fmt::Display::fmt(error, out),
            Self::Decision(error) => fmt::Display::fmt(error, out),
        }
    }
}

impl std::error::Error for HistoryStepRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Body(error) => Some(error.as_ref()),
            Self::Checkpoint(error) => Some(error.as_ref()),
            Self::Decision(error) => Some(error),
            _ => None,
        }
    }
}

fn live(is_cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), HistoryStepRefusal> {
    if is_cancelled() {
        Err(HistoryStepRefusal::Cancelled)
    } else {
        Ok(())
    }
}

/// Read and verify one predecessor edge of an authenticated authority history.
///
/// `successor` must be the authenticated current head or a predecessor reached
/// through an earlier verified step. The function does not accept a client
/// supplied immutable head as published authority. It charges every predecessor
/// edge before I/O against the caller's bound capped by [`MAX_REPLAY_BATCHES`],
/// and polls the caller's cancellation predicate around each immutable read.
/// Equal decision tails select the strict capsule verifier; every other edge
/// must satisfy the existing complete decision-batch verifier.
pub async fn read_history_step_async<S>(
    store: &S,
    cx: &S::Context,
    successor: &RepositoryAuthorityHeadBody,
    walked: &mut usize,
    maximum_steps: usize,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> Result<HistoryStep, HistoryStepRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    live(is_cancelled)?;
    let Some(predecessor_id) = successor.predecessor_head_id else {
        return if successor.decision_tail_id.is_none() {
            Ok(HistoryStep::Genesis)
        } else {
            Err(HistoryStepRefusal::UnboundHead)
        };
    };
    // Every non-genesis edge is either a decision (the successor names its
    // decision tail) or a checkpoint (the successor names its capsule). A head
    // that names a predecessor but neither is structurally unbound; refuse it
    // before reading anything, rather than reporting whichever predecessor
    // read happens to fail first.
    if successor.decision_tail_id.is_none() && successor.last_checkpoint_id.is_none() {
        return Err(HistoryStepRefusal::UnboundHead);
    }
    let limit = maximum_steps.min(MAX_REPLAY_BATCHES);
    if *walked >= limit {
        return Err(HistoryStepRefusal::BoundExceeded { limit });
    }
    *walked += 1;
    let read = read_authority_head_body_async(store, cx, predecessor_id).await;
    live(is_cancelled)?;
    let predecessor = read.map_err(|error| HistoryStepRefusal::Body(Box::new(error)))?;
    let basis = PublicationBasis::new(predecessor_id, predecessor);

    if successor.decision_tail_id == basis.body().decision_tail_id {
        let capsule_id = successor.last_checkpoint_id.ok_or_else(|| {
            HistoryStepRefusal::Checkpoint(Box::new(
                CheckpointTransitionRefusal::CheckpointNotAdvanced,
            ))
        })?;
        let key = body_key_for_id(capsule_id.as_internal_object_id())
            .map_err(|error| HistoryStepRefusal::Body(Box::new(error.into())))?;
        let read = store.read_immutable(cx, &key).await;
        live(is_cancelled)?;
        let ImmutableRead::Present(bytes) = read.map_err(HistoryStepRefusal::Authority)? else {
            return Err(HistoryStepRefusal::CapsuleAbsent(capsule_id));
        };
        verify_checkpoint_successor(&basis, successor, &bytes)
            .map_err(|error| HistoryStepRefusal::Checkpoint(Box::new(error)))?;
        live(is_cancelled)?;
        return Ok(HistoryStep::Checkpoint { predecessor: basis });
    }

    let batch_id = successor
        .decision_tail_id
        .ok_or(HistoryStepRefusal::UnboundHead)?;
    let read = read_decision_batch_body_async(store, cx, batch_id).await;
    live(is_cancelled)?;
    let batch = read.map_err(|error| HistoryStepRefusal::Body(Box::new(error)))?;
    verify_pair(&CryptoBodyIdentity, &basis, &batch, successor)
        .map_err(HistoryStepRefusal::Decision)?;
    live(is_cancelled)?;
    Ok(HistoryStep::Decision {
        predecessor: basis,
        batch,
    })
}
