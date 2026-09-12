//! Shared metadata-only canonical publication. PR and issue commands use this
//! exact seal/recovery/prepare/CAS loop; domain validators cannot move Git refs.
use std::future::Future;
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, OutcomeLookup, SealAttempt, TerminalOutcome};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::ForgeEvent;
use fgit_types::RefusalCode;
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure, ValidatedClosure};
use super::{NativeMergeProjection, PreparationFailure, prepare_event, stage_prepared, storage, unavailable};
use super::super::NativeMergeBasis;

pub(super) trait MetadataValidation<S, P>: Sync
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &AdmissionSnapshot) -> Result<(), ProjectionFailure>;
    fn validate<'a>(&'a self, store: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        snapshot: &'a AdmissionSnapshot, resolved: &'a NativeMergeBasis,
        event: &'a ForgeEvent, projection: &'a P,
    ) -> impl Future<Output = Result<ValidatedClosure, PreparationFailure>> + Send + 'a;
}

pub(super) async fn admit_metadata_async<S, P, V>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    event: ForgeEvent, attempt: SealAttempt, limits: AdmissionLimits,
    projection: &P, validation: &V,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
    V: MetadataValidation<S, P> + ?Sized,
{
    limits.validate()?;
    if !attempt.request.ref_commands().is_empty() { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    for _ in 0..limits.max_cas_replans {
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        if let OutcomeLookup::Decided(outcome) = fgit_authority::resolve_outcome_async(
            store, cx, &context.head_key, context.tenant_id, context.repository_id, tx_id,
        ).await? { return Ok(outcome); }
        let (basis, receipt, authenticated) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() { continue; }
        let prepared: Result<_, PreparationFailure> = async {
            let snapshot = projection.snapshot_async(store, cx, &basis, &authenticated).await?;
            validation.precheck(&snapshot)?;
            let resolved = projection.resolve_merge_basis_async(store, cx, &basis, &authenticated).await?;
            if resolved.refs.refs() != &snapshot.refs
                || resolved.refs.head_target() != snapshot.head_target.as_ref()
                || storage::load_forge_positions(store, cx, &basis).await? != resolved.forge
            { return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into()); }
            projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            let closure = validation.validate(store, cx, &basis, &authenticated,
                &snapshot, &resolved, &event, projection).await?;
            let prepared = prepare_event(context, &event, &closure, tx_id, &attempt, &basis, &resolved)
                .map_err(ProjectionFailure::Refuse)?;
            if prepared.materialization.roots.ref_root != basis.body().ref_root
                || prepared.refs != resolved.refs
                || !prepared.fold.effects().is_some_and(|effects| effects.refs.is_empty())
            { return Err(ProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach).into()); }
            Ok(prepared)
        }.await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => return Err(unavailable(code)),
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
                if let Some(outcome) = crate::publish_refusal_async(
                    store, cx, context, &basis, receipt.token(), admission.seal_id(), tx_id,
                    code, projection, &cumulative,
                ).await? { return Ok(outcome); }
                continue;
            }
        };
        stage_prepared(store, cx, &prepared).await?;
        projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(prepared.materialization.record);
        let publication = plan.seal(&CryptoBodyIdentity, prepared.materialization.roots, &cumulative, receipt.token())?;
        projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
        if let Some(outcome) = crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication).await? {
            return Ok(outcome);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded { limit: limits.max_cas_replans })
}
