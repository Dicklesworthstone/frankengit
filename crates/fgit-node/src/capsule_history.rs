//! Native materialization errors for the shared authenticated history reader.

use fgit_authority::{AsyncAuthorityStore, MAX_REPLAY_BATCHES, OutcomeFailure};
use fgit_chronicle::{HistoryStepRefusal, read_history_step_async};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_types::Digest;

use crate::AdmissionMaterializationRefusal;

pub(crate) use fgit_chronicle::HistoryStep;

pub(crate) async fn predecessor_in<S>(
    store: &S,
    cx: &S::Context,
    successor: &RepositoryAuthorityHeadBody,
    walked: &mut usize,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> Result<HistoryStep, AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    read_history_step_async(
        store,
        cx,
        successor,
        walked,
        MAX_REPLAY_BATCHES,
        is_cancelled,
    )
    .await
    .map_err(|error| match error {
        HistoryStepRefusal::Cancelled => AdmissionMaterializationRefusal::Cancelled,
        HistoryStepRefusal::BoundExceeded { limit } => {
            AdmissionMaterializationRefusal::DecisionHistory(Box::new(
                OutcomeFailure::ReplayBoundExceeded { limit },
            ))
        }
        HistoryStepRefusal::UnboundHead => AdmissionMaterializationRefusal::DecisionHistoryUnbound,
        HistoryStepRefusal::Authority(error) => AdmissionMaterializationRefusal::Authority(error),
        HistoryStepRefusal::Body(error) => AdmissionMaterializationRefusal::DecisionHistory(error),
        HistoryStepRefusal::CapsuleAbsent(id) => {
            let id = id.as_internal_object_id();
            AdmissionMaterializationRefusal::ImmutableAbsent(Digest::new(
                id.algorithm(),
                *id.digest(),
            ))
        }
        HistoryStepRefusal::Checkpoint(error) => {
            AdmissionMaterializationRefusal::CheckpointTransition(error)
        }
        HistoryStepRefusal::Decision(error) => {
            AdmissionMaterializationRefusal::DecisionHistoryVerification(error)
        }
    })
}
