//! Canonical publication of immutable workflow observations, never green checks.
//!
//! The existing metadata admission loop owns seals, terminal recovery, immutable
//! staging and the only authority-head CAS. A configured projection verifies the
//! actual source and evidence; this module never trusts a journal as authority.
use std::future::Future;

use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::PublicationBasis;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_forge::event::workflow_check::{NativeWorkflowCheck, WorkflowCheckId, WorkflowCheckRecord};
use fgit_types::{AsciiSlug, RefusalCode};

use super::{NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable};
use super::super::NativeMergeBasis;
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure, ValidatedClosure};

/// The trusted boundary authenticates source objects and interprets the retained
/// execution evidence. It may not turn an ActionRequired observation into a
/// successful check. Unavailable evidence leaves the sealed request retryable.
pub trait WorkflowCheckProjection<S: AsyncAuthorityStore + ?Sized>: NativeMergeProjection<S> {
    fn validate_workflow_check_async<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        record: &'a WorkflowCheckRecord,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// Exact logical submission. Both event content and inline evidence enter the
/// seal. Retry identities do not depend on the mutable current authority head.
pub fn proposal(
    context: &AdmissionContext,
    record: &WorkflowCheckRecord,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = record.proposed_event(context.principal_id, context.object_format)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("workflow-check.event-batch-root.v1"),
            root.bytes().as_bytes(),
        )?],
    )?;
    Ok((event, SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request,
    }))
}

/// Record the authenticated publisher's exact observation plus its delivery
/// obligation atomically. No ref command is admitted. Exact terminal retries
/// resolve before source/aggregate freshness checks, including after ref movement.
pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    record: &WorkflowCheckRecord,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: WorkflowCheckProjection<S> + ?Sized,
{
    limits.validate()?;
    let (event, attempt) = proposal(context, record)?;
    metadata::admit_metadata_async(store, cx, context, event, attempt, limits, projection, &Validation(record)).await
}

struct Validation<'a>(&'a WorkflowCheckRecord);
impl<S, P> metadata::MetadataValidation<S, P> for Validation<'_>
where
    S: AsyncAuthorityStore + ?Sized,
    P: WorkflowCheckProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        if snapshot.hidden_refs.hides(self.0.source_ref.as_bytes()) {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized));
        }
        Ok(())
    }
    async fn validate<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        snapshot: &'a AdmissionSnapshot,
        resolved: &'a NativeMergeBasis,
        event: &'a ForgeEvent,
        projection: &'a P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        if snapshot.refs.get(&self.0.source_ref) != Some(&self.0.source_commit) {
            return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
        }
        // An observation stream is immutable. The canonical outcome lookup in
        // the shared driver, not a second event append, implements exact retries.
        let label = storage::aggregate_label(event.aggregate)?;
        if resolved.forge.entry(label).is_some() {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
        Ok(projection.validate_workflow_check_async(store, cx, basis, authenticated, self.0).await?)
    }
}

/// Read one immutable observation through an authenticated selected forge root.
/// This proves what was recorded, not execution truth or permission to merge.
/// The serving boundary must apply current source-ref visibility before disclosure.
pub async fn read_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    id: WorkflowCheckId,
    cancelled: &C,
) -> Result<Option<NativeWorkflowCheck>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    if cancelled() { return Err(unavailable(RefusalCode::CancellationInProgress)); }
    let selected = delivery::read_in(store, cx, basis, cancelled).await?;
    let aggregate = AggregateId::WorkflowCheck(id);
    let label = storage::aggregate_label(aggregate)?;
    let Some(frontier) = selected.forge.entry(label) else { return Ok(None); };
    if frontier.successor_position() != 1 {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let batch = storage::read_events(store, cx, basis.body().repository_id, frontier.event_batch_root()).await?;
    if cancelled() { return Err(unavailable(RefusalCode::CancellationInProgress)); }
    let mut matches = batch.events.into_iter().filter(|event| event.aggregate == aggregate);
    let event = matches.next().ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    if matches.next().is_some() || event.version != AggregateVersion::FIRST {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let ForgeEventPayload::WorkflowCheckObservedNative(change) = event.payload else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    if change.id() != id {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(Some(change))
}

#[cfg(test)]
mod tests;
