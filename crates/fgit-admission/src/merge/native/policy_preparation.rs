//! Read-only preparation of the original sealed-package evidence contract.
//! Activation changes policy evidence but never the original request identity.
use super::{
    NativeMergeIntent, NativeMergeProjection, PreparationFailure, prepare_event, protection,
    storage, unavailable,
};
use crate::merge::{NativeMergeBasis, SealedMerge};
use crate::{AdmissionContext, AdmissionError, CommitEvidence, ProjectionFailure};
use fgit_authority::AsyncAuthorityStore;
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, ForgeEventPayload};
use fgit_types::{PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};

/// A pre-publication observation, never an authorization or publication receipt.
/// Admission independently revalidates it at its actual CAS basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedSealedMergeEvidence {
    pub basis: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    pub tx_id: TxId,
    pub evidence: CommitEvidence,
}

/// Prepare exact evidence for an original native sealed package, optionally
/// under its explicit workspace-snapshot seal profile. No request seal or body
/// is written. The projection verifies native objects and current review/check
/// gates; the existing whole-fold builder computes every evidence identity.
/// `sealed.evidence` is deliberately ignored here because it is the output.
pub async fn prepare_sealed_native_merge_evidence_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    workspace_snapshot: Option<[u8; 32]>,
    projection: &P,
) -> Result<PreparedSealedMergeEvidence, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let run: Result<_, PreparationFailure> = async {
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let maximum = super::objects::MergeObjectLimits::default().max_objects;
        if sealed.package.objects.len() > maximum || sealed.closure.objects.len() > maximum {
            return Err(ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded).into());
        }
        let ForgeEventPayload::MergeCommittedNative(merge) = &sealed.package.event.payload else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let AggregateId::PullRequest(number) = sealed.package.event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        if merge.merge_commit.algorithm() != context.object_format {
            return Err(AdmissionError::ObjectFormatMismatch.into());
        }
        let expected = AggregateVersion::try_new(sealed.package.event.version.get() - 1)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly);
        let intent = NativeMergeIntent::new(number, expected, merge.clone())?;
        if intent.event() != &sealed.package.event {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        }
        let attempt = match workspace_snapshot {
            None => crate::merge::seal_attempt_for(context, sealed)?,
            Some(digest) => super::workspace::workspace_seal_attempt_for(context, sealed, digest)?,
        };
        let tx_id = attempt.derive().map_err(AdmissionError::from)?.0;
        let (basis, _, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        let snapshot = projection
            .snapshot_async(store, cx, &basis, &authenticated)
            .await?;
        if snapshot.hidden_refs.hides(merge.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(merge.target_ref.as_bytes())
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }
        crate::merge::check_against_snapshot(sealed, &snapshot)
            .map_err(|why| ProjectionFailure::Refuse(why.refusal_code()))?;
        let resolved: NativeMergeBasis = projection
            .resolve_merge_basis_async(store, cx, &basis, &authenticated)
            .await?;
        if resolved.refs.refs() != &snapshot.refs
            || resolved.refs.head_target() != snapshot.head_target.as_ref()
            || storage::load_forge_positions(store, cx, &basis).await? != resolved.forge
        {
            return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into());
        }
        if let Some(code) = storage::aggregate_refusal(store, cx, &resolved.forge, &intent).await? {
            return Err(ProjectionFailure::Refuse(code).into());
        }
        let closure = projection
            .validate_merge_async(store, cx, &basis, &authenticated, &intent)
            .await?;
        if &closure != sealed.closure
            || sealed
                .package
                .objects
                .iter()
                .any(|oid| !closure.objects.contains(oid))
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete).into());
        }
        let mut prepared = prepare_event(
            context,
            &sealed.package.event,
            &closure,
            tx_id,
            &attempt,
            &basis,
            &resolved,
        )
        .map_err(ProjectionFailure::Refuse)?;
        protection::attach_prepared_policy_selected_at(
            store,
            cx,
            context,
            &basis,
            &resolved,
            &mut prepared,
            crate::evidence::RefPolicyPublication::NativeMerge,
            projection.admission_authentication(),
            None,
            &|| projection.merge_checkpoint(cx).is_err(),
        )
        .await?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let record = prepared.materialization.record;
        Ok(PreparedSealedMergeEvidence {
            basis: basis.id(),
            policy_epoch: basis.body().policy_epoch,
            tx_id,
            evidence: CommitEvidence {
                principal_snapshot_id: record.principal_snapshot_id,
                forge_event_batch_root: record.forge_event_batch_root,
                policy_decision_root: record.policy_decision_root,
                invariant_evidence_root: record.invariant_evidence_root,
                outbox_effect_root: record.outbox_effect_root,
                retention_delta_root: record.retention_delta_root,
            },
        })
    }
    .await;
    match run {
        Ok(value) => Ok(value),
        Err(PreparationFailure::Admission(error)) => Err(*error),
        Err(PreparationFailure::Projection(
            ProjectionFailure::Refuse(code) | ProjectionFailure::Unavailable(code),
        )) => Err(unavailable(code)),
    }
}
