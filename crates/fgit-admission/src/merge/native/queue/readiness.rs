//! Read-only evaluation of a candidate landing through the publication driver's
//! complete preparation. A waiting review or check must not consume a landing
//! key by publishing a permanent refusal merely to observe readiness.

use fgit_authority::AsyncAuthorityStore;
use fgit_types::{PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};

use super::super::{
    NativeMergeProjection, PreparationFailure, prepare_merge_attempt_at, unavailable,
    validate_prepared,
};
use super::{Landing, QueueCandidateLandingCommand, candidate_landing_proposal};
use crate::{AdmissionContext, AdmissionError, ProjectionFailure};

/// The complete landing preparation's observation at one authenticated head.
/// `refusal == None` means that preparation succeeded at this basis; it grants
/// no permission, reserves no request key and never survives a later replan.
/// Actual admission independently executes the same preparation again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateLandingReadiness {
    pub basis: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    pub tx_id: TxId,
    pub refusal: Option<RefusalCode>,
}

/// Inspect the exact two-parent queue-head command without sealing it or
/// publishing any objects, bodies, outcomes or authority transitions. Native
/// object validation, authentication, queue/PR/ref/policy guards and review/check
/// evidence are the same code used by actual candidate landing admission.
///
/// Evaluated semantic refusals are returned as observations. Missing required
/// infrastructure or unverifiable material and cancellation remain errors;
/// they are never reported as a completed preparation or terminal decision.
/// The candidate objects must already be available to the projection, as after
/// the watcher's ordinary CI-branch publication.
///
/// This observes current state, not an earlier request's outcome. A caller that
/// previously submitted the same command must recover its original terminal
/// outcome separately; later readiness cannot rewrite that decision.
pub async fn inspect_candidate_landing_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &QueueCandidateLandingCommand,
    projection: &P,
) -> Result<CandidateLandingReadiness, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let intent = command.intent()?;
    let (events, attempt) = candidate_landing_proposal(context, command)?;
    let tx_id = attempt.derive().map_err(AdmissionError::from)?.0;
    let (basis, _, authenticated) =
        crate::read_basis_async(store, cx, &context.head_key).await?;
    let preparation = prepare_merge_attempt_at(
        store,
        cx,
        context,
        &intent,
        &attempt,
        None,
        tx_id,
        &basis,
        &authenticated,
        projection,
        Some(Landing::Candidate(command)),
        Some(&events),
    )
    .await;
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let refusal = match preparation {
        Ok(prepared) => {
            validate_prepared(&prepared)?;
            projection
                .merge_publication_checkpoint(cx)
                .map_err(unavailable)?;
            None
        }
        Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => Some(code),
        Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => {
            return Err(unavailable(code));
        }
        Err(PreparationFailure::Admission(error)) => return Err(*error),
    };
    Ok(CandidateLandingReadiness {
        basis: basis.id(),
        policy_epoch: basis.body().policy_epoch,
        tx_id,
        refusal,
    })
}
